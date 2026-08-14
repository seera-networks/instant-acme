# PKCS#10 CSR による証明書発行の強化計画

対象リビジョン: `268e2db`（instant-acme 0.9.0）

## 0. TL;DR

- **前提の訂正**: instant-acme は既に外部生成の CSR を受け付ける。`Order::finalize_csr(csr_der: &[u8])`（`src/order.rs:90`）に PKCS#10 の DER を渡せば、instant-acme に秘密鍵を一切触らせずに証明書を発行できる。鍵の自動生成が必須なのは `Order::finalize()`（`src/order.rs:65`、`rcgen` + 暗号バックエンド feature が必要）だけである。
- **本当に足りていないもの**は次の 4 点:
  1. 入力が `&[u8]` の DER のみ。PEM (`-----BEGIN CERTIFICATE REQUEST-----`) を直接渡せない。
  2. 送信前の検証が皆無。オーダーの identifier と CSR の SAN が食い違っていても、サーバに投げて `badCSR` が返るまで分からない。
  3. 外部鍵（HSM / KMS / 既存の鍵ファイル）から CSR を作る導線がドキュメント・サンプルの両方に存在しない。README も `finalize()` 中心。
  4. `finalize_csr` は「CSR を渡す」以上の型情報を持たないため、誤って証明書 DER や PEM バイト列を渡してもコンパイルは通る。
- **方針**: 新しいプロトコル層を作るのではなく、(A) CSR 入力の型付けと PEM 対応、(B) 任意有効化の事前検証、(C) 外部署名鍵ワークフローの例とドキュメント、の 3 段階で積み上げる。ASN.1 エンコーダを instant-acme に持ち込むことは避ける。

---

## 1. 現状分析

### 1.1 発行経路

```
Account::new_order()  ->  Order (pending)
        認証チャレンジ処理
Order::poll_ready()   ->  Ready
        ┌─ Order::finalize()      … rcgen で鍵生成 + CSR 生成 -> finalize_csr()
        └─ Order::finalize_csr()  … 呼び出し側が用意した CSR(DER) をそのまま送信
Order::poll_certificate() -> PEM チェイン
```

該当コード:

- `src/order.rs:65` `finalize()` — `CertificateParams::new(names)` + `KeyPair::generate()` + `serialize_request()`。生成した秘密鍵を PEM 文字列で返す。`#[cfg(all(feature = "rcgen", any(feature = "aws-lc-rs", feature = "ring")))]`。
- `src/order.rs:90` `finalize_csr(&mut self, csr_der: &[u8])` — feature ゲートなし。常に利用可能。
- `src/types.rs:243` `FinalizeRequest { csr: String }` — `BASE64_URL_SAFE_NO_PAD` で符号化して POST（RFC 8555 §7.4）。

つまり「秘密鍵を instant-acme に渡さない発行」は今日すでに動く。以下は既存 API だけで書ける最小例:

```rust
// 鍵は HSM の中、CSR は外部で生成済み（DER バイト列）
let csr_der: Vec<u8> = load_csr_from_somewhere()?;
order.finalize_csr(&csr_der).await?;
let chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;
```

### 1.2 不足点の詳細

| # | 不足 | 影響 |
| --- | --- | --- |
| 1 | PEM 入力不可 | 実運用の CSR は PEM で保管・受け渡しされることが多い。呼び出し側が毎回 base64 デコードを自作する（PEM パーサの自作はバグの温床） |
| 2 | 事前検証なし | identifier と SAN の不一致・鍵長不足などがサーバ往復後にしか分からない。ACME サーバのレート制限とオーダーを 1 つ無駄に消費する。エラーも `Problem` 由来で原因が特定しにくい |
| 3 | 外部鍵の CSR 生成導線なし | 「鍵を出さずに発行したい」利用者が最初に詰まるのはここ。instant-acme 側の変更が不要でも、方法が示されていなければ使えないのと同じ |
| 4 | 型が `&[u8]` | 取り違えを型で防げない。`rustls-pki-types` には `CertificateSigningRequestDer` があるのに使っていない |
| 5 | README / examples が `finalize()` 前提 | `provision.rs` は `order.finalize()` を呼び、秘密鍵 PEM をログ出力する。CSR 経路のサンプルがない |

### 1.3 既に手元にある道具（新規依存が不要な根拠）

- `rustls-pki-types`（**必須依存**、現在 `"1.1.0"` 指定）に `CertificateSigningRequestDer<'a>` と `pem::PemObject` があり、`from_pem_slice` / `from_pem_file` が使える（1.15.0 および 1.12.0 のソースで確認済み。正確な導入バージョンは crates.io で要確認、最低 1.12 への引き上げを想定）。PEM 対応は**新規クレートの追加なし**で実現できる。
  - ただし `from_pem_file` は `#[cfg(feature = "std")]`（`rustls-pki-types` の `src/pem.rs:36`）。instant-acme の依存宣言は features 指定なしで、`rustls-pki-types` の default は `["alloc"]` のみ。現状 `std` は `rustls` / `hyper-rustls` 経由でしか有効にならず、`--no-default-features --features aws-lc-rs`（HTTP クライアント持ち込み構成）では `from_pem_file` がコンパイルできない。**依存宣言に `features = ["std"]` を明示する**こと。他クレートの feature 有効化に依存する状態は、本書 §3 フェーズ 2 で自ら警告している feature unification 依存そのものになる。
- `Cargo.toml` の `package.metadata.cargo_check_external_types.allowed_external_types` に `rustls_pki_types::*` が既に入っている。公開 API に出しても外部型チェックを通る。
- `x509-parser`（既存の optional 依存、`x509-parser` feature）に `X509CertificationRequest` があり、**追加 feature なし**で CSR のパースと `requested_extensions()` が使える。署名検証 `verify_signature()` だけ `verify`（ring）/ `verify-aws`（aws-lc-rs）feature が必要で、これは instant-acme の既存バックエンド feature に素直に対応付けられる。
- `rcgen` 0.14（既存の optional 依存）は公開トレイト `SigningKey: PublicKeyData` を持ち、`CertificateParams::serialize_request(&impl SigningKey)` に**外部実装の署名器**を渡せる。KMS/HSM 署名の CSR 生成は instant-acme 本体を変更せずに書ける。

---

## 2. ゴールと非ゴール

### ゴール

1. CSR を **DER でも PEM でも**、型付きの API で渡せる。
2. 送信前にローカルで CSR を検証し、オーダーとの不整合を **ACME 往復なしで** 検出できる（任意有効化）。
3. `rcgen` feature を無効にした構成（＝instant-acme が鍵生成コードを一切含まない構成）で、実運用の完全なワークフローがサンプルとドキュメントで示されている。
   - **前提となる修正**: 現在の `Cargo.toml` は `aws-lc-rs = [..., "rcgen/aws_lc_rs"]` と `?` なしで書かれているため、暗号バックエンドを有効にすると optional な `rcgen` まで有効化される。`cargo tree -e features --no-default-features --features hyper-rustls,aws-lc-rs` で `rcgen v0.14.7` が入ることを確認済み。`rcgen?/aws_lc_rs` / `rcgen?/ring` に直さないとこのゴールは達成できない。
4. 既存の `finalize_csr(&[u8])` 利用コードを壊さない、あるいは壊す場合は移行手順を明示する。

### 非ゴール

- instant-acme 自身に ASN.1 (DER) エンコーダを持たせて CSR を組み立てること。`yasna` / `der` などの新規依存はコスト対効果が悪く、上流の依存方針にも合わない。CSR 生成は `rcgen`（またはユーザ側の任意実装）に委ねる。
- アカウント鍵用の `SigningKey` トレイト（`src/crypto.rs:80`）を CSR 署名に流用すること。当該トレイトは JWK 出力と JWS `alg` を前提としており、CSR には SubjectPublicKeyInfo と X.509 の `AlgorithmIdentifier` が要る。設計が別物なので拡張ではなく別トレイト、もしくは rcgen 委譲とする。
- PKCS#11 / KMS クライアントの同梱。あくまで「差し込めること」を保証する。
- CSR に任意の X.509 拡張（EKU、Subject DN 等）を積む機能。ACME CA はそのほとんどを無視するため、必要なら呼び出し側が rcgen で組む。

---

## 3. 設計

### フェーズ 1: CSR 入力の型付けと PEM 対応

新しい型を `src/types.rs`（または `src/order.rs`）に追加する。

```rust
/// 発行対象の PKCS#10 証明書署名要求（RFC 2986）
#[derive(Clone, Debug)]
pub struct Csr<'a>(CertificateSigningRequestDer<'a>);

impl<'a> Csr<'a> {
    /// DER エンコードされた CSR から構築する
    pub fn from_der(der: impl Into<CertificateSigningRequestDer<'a>>) -> Self;

    /// PEM (`CERTIFICATE REQUEST`) から構築する
    pub fn from_pem(pem: &[u8]) -> Result<Csr<'static>, Error>;

    /// PEM ファイルから読み込む（`rustls-pki-types` の `std` feature が必要）
    pub fn from_pem_file(path: impl AsRef<Path>) -> Result<Csr<'static>, Error>;

    /// DER バイト列を借用する
    pub fn der(&self) -> &[u8];
}

impl<'a> From<&'a [u8]> for Csr<'a> { /* ... */ }
impl<'a> From<&'a CertificateSigningRequestDer<'a>> for Csr<'a> { /* ... */ }
```

`from_pem` / `from_pem_file` は `rustls_pki_types::pem::PemObject` に委譲する（`from_pem_file` は `std` feature 前提。instant-acme は既に `hyper-rustls` 経路で `PemObject` を使用中）。

API 変更の選択肢:

| 案 | 内容 | 評価 |
| --- | --- | --- |
| A | `finalize_csr` のシグネチャを `csr: impl Into<Csr<'_>>` に変更 | API 面が増えない。ただし **deref 強制が効かなくなる**破壊的変更を含む。現在 `finalize_csr(csr.der())` は `&CertificateSigningRequestDer` → `&[u8]` の deref coercion に依存しており、ジェネリック化すると coercion が働かない。`From<&CertificateSigningRequestDer>` を実装すれば救済できるが、他の `Deref<Target = [u8]>` な型を渡していた利用者はコンパイルエラーになる |
| B | `finalize_csr(&[u8])` を残し、`finalize(csr: Csr<'_>)` 系の新メソッドを追加 | 完全後方互換。ただし `finalize` は既に鍵生成版が占有しており命名が衝突する |
| **C（推奨）** | `finalize_csr(&[u8])` を維持しつつ、`Order::finalize_with(&mut self, csr: &Csr<'_>)` を追加。`finalize_csr` は `finalize_with` への薄いラッパにする | 後方互換かつ型付き経路を提供。将来 `finalize_csr` を `#[deprecated]` にして 0.10 で整理できる |

**推奨は C**。0.x なので A も許容範囲だが、破壊的変更は検証機能（フェーズ 2）と同じリリースにまとめて 1 回で済ませるほうがよい。

### フェーズ 2: 送信前検証

検証は **`Order` のメソッド**として実装する。`x509-parser` feature 有効時のみ。

```rust
#[cfg(feature = "x509-parser")]
impl Order {
    /// CSR がこのオーダーに対して妥当かをローカルで検査する
    ///
    /// authorization の状態が未取得の場合のみ取得のための往復が発生する。
    /// 検査そのものはネットワークアクセスを伴わない。
    pub async fn validate_csr(&mut self, csr: &Csr<'_>) -> Result<(), CsrError>;
}

/// オフライン検査用の下位 API（`Order` を持たない場面向け）
#[cfg(feature = "x509-parser")]
impl Csr<'_> {
    pub fn validate(&self, identifiers: &[AuthorizedIdentifier<'_>]) -> Result<(), CsrError>;
}
```

**なぜ `Csr::validate(&[Identifier])` ではないのか**（初版の設計ミス）:

- **ワイルドカードの情報が `Identifier` に無い。** `*.example.com` のオーダーでも authorization の identifier は `Identifier::Dns("example.com")` であり、ワイルドカードかどうかは `AuthorizedIdentifier::wildcard`（`src/types.rs:766-777`）が保持している。`Identifier` のスライスだけを渡すと、正しい CSR（SAN が `*.example.com`）が `MissingIdentifier` かつ `UnexpectedIdentifier` の二重誤判定になる。
- **アカウント鍵に触れない。** 下記の検査 5（RFC 8555 §11.1）はアカウント鍵の公開鍵が必要で、`Csr` 単体では実装不可能。`Order` は `Arc<AccountInner>` を通じて鍵にアクセスできる。

したがって、ワイルドカードとアカウント鍵の両方を見られる `Order::validate_csr()` を主 API とし、`Csr::validate()` は `AuthorizedIdentifier` を受け取るオフライン用の補助（検査 5 は行わない）と位置づける。

検査項目（RFC 8555 §7.4 / §11.1 と Boulder の実挙動に基づく）:

1. **DER としてパースできるか** — `X509CertificationRequest::from_der`。
2. **SAN のカバレッジ** — オーダーの各 identifier（`Identifier::Dns` / `Identifier::Ip`、ワイルドカードは `AuthorizedIdentifier` の `wildcard` ビットを考慮）が CSR の `subjectAltName` に含まれるか。DNS 名は ASCII 小文字化して比較、IP は `IpAddr` として正規化して比較（文字列比較だと IPv6 表記揺れで誤判定する）。
3. **余剰 SAN の検出** — CSR にオーダー外の名前があると CA は拒否する。エラーにするか警告に留めるかは要検討（デフォルトはエラー、`allow_extra_names()` で緩和）。
4. **CN の扱い** — Subject CN があるのに SAN に無い場合、Boulder は拒否する。検出してエラーにする。
5. **アカウント鍵の再利用禁止**（RFC 8555 §11.1）— CSR の公開鍵がアカウント鍵と一致したらエラー。やらかすと CA から拒否され原因が分かりにくいので実利は大きい。`Order::validate_csr()` でのみ実施。実装は CSR の SubjectPublicKeyInfo からアカウント鍵と同じ表現（JWK サムプリント等）を導いて比較する形になるため、instant-acme が JWK 化できる鍵種別（現状 P-256）以外では比較をスキップする。
6. **署名検証**（任意）— `verify_signature()`。`x509-parser` の `verify` / `verify-aws` feature が要るため、instant-acme 側で `x509-parser?/verify-aws`（`aws-lc-rs` 有効時）/ `x509-parser?/verify`（`ring` 有効時）へマッピングする。既存の `rcgen/aws_lc_rs`・`rcgen/ring` と同じ書き方で `Cargo.toml` の `[features]` に足せる。

**呼び出しタイミングの設計上の論点**: `finalize_with` が feature 有効時に暗黙で `validate()` を呼ぶ設計は、Cargo の feature unification によって「別のクレートが `x509-parser` を有効化したせいで挙動が変わる」問題を招く。したがって**暗黙呼び出しはしない**。検証は呼び出し側が明示的に行い、ドキュメントとサンプルで強く推奨する。

```rust
let csr = Csr::from_pem_file("server.csr")?;

order.validate_csr(&csr).await?;     // 事前検査（ACME の finalize 往復は発生しない）
order.finalize_with(&csr).await?;
```

エラー型は `CsrError` を公開型として定義し、`Error::Csr(CsrError)` を追加する。`Error` は既に `#[non_exhaustive]`（`src/types.rs:23-26`）なので、variant 追加は破壊的変更にならない。`Error::Other(Box<...>)` に包む案（`Error::from_rcgen`、`src/types.rs:68` と同様）もあるが、呼び出し側が原因別に分岐できるほうが有用。

### フェーズ 3: 外部署名鍵（HSM / KMS）での CSR 生成

instant-acme 本体の変更は不要。rcgen 0.14 の公開トレイトを実装すればよい、という事実をドキュメントと例で示す。

```rust
// KMS 上の鍵を rcgen の署名器として見せる
struct KmsKey { public_key: Vec<u8>, handle: KmsHandle }

impl rcgen::PublicKeyData for KmsKey {
    /// SPKI **ではなく**、SPKI の BIT STRING の中身（P-256 なら 0x04 || X || Y の 65 バイト）
    fn der_bytes(&self) -> &[u8] { &self.public_key }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for KmsKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.handle.sign_blocking(msg)   // 下記の注意を参照
    }
}

let mut params = rcgen::CertificateParams::new(names)?;
params.distinguished_name = rcgen::DistinguishedName::new();   // CN を空に（Boulder 対策）
let csr = params.serialize_request(&kms_key)?;
order.finalize_with(&Csr::from_der(csr.der().as_ref())).await?;
```

`csr.der()` は `&CertificateSigningRequestDer<'static>` を返すが、`Csr::from_der` の引数は `impl Into<CertificateSigningRequestDer<'a>>` で、`rustls-pki-types` が提供する `From` 実装は `From<&[u8]>` と `From<Vec<u8>>` のみ。ジェネリックな型引数には deref 強制が効かないため `.as_ref()` が要る（これは §3 フェーズ 1 の案 A が破壊的になる理由と同じ現象）。頻出パターンなので、instant-acme 側で `impl<'a> From<&'a CertificateSigningRequestDer<'a>> for Csr<'a>` を用意して `.as_ref()` を不要にすることも検討する。

**注意点（ドキュメントに明記すべき事項）**:

- `rcgen::SigningKey::sign` は **同期**。非同期な KMS クライアントを直接呼べない。Tokio ランタイム上では `tokio::task::block_in_place`（multi-thread ランタイム限定）、または CSR 生成全体を `spawn_blocking` に載せる。current-thread ランタイムでの `block_on` 再入はデッドロックするので回避策を書く。
- ECDSA 署名は **ASN.1 DER (SEQUENCE of two INTEGER)** で返す必要がある。AWS KMS の `ECDSA_SHA_256` は DER を返すのでそのままでよいが、raw r||s を返す HSM では変換が要る。
- `sign` に渡ってくる `msg` は **ハッシュ前のメッセージ**。ハッシュを外部で行う KMS（digest 入力 API）を使う場合は自前で SHA-256 してから digest モードで投げる。
- `PublicKeyData::der_bytes()` が返すのは **SPKI そのものではない**。rcgen 側の `serialize_public_key_der`（`src/key_pair.rs:779-785`）が `AlgorithmIdentifier` と BIT STRING でラップするため、ここに AWS KMS の `GetPublicKey` が返す SPKI をそのまま入れると SPKI が二重に包まれ、CA に拒否される CSR ができる。KMS から取得した SPKI は BIT STRING の中身を取り出してから渡すこと。
- 鍵種別の対応表（P-256 / P-384 / RSA-2048 / RSA-4096 と対応する `rcgen::SignatureAlgorithm` 定数）を載せる。ACME CA 側の制約（Let's Encrypt は RSA 2048〜4096、P-256/P-384 のみ、Debian weak key 拒否）も併記する。

さらに、**CSR を rcgen すら使わず外部（OpenSSL / cfssl / 別チーム）で作る**ケースが実運用では最も多い。この場合 instant-acme は `Csr::from_pem_file` で読むだけになる。この経路を README の第一級のサンプルとして載せる。

```bash
# 鍵は一度もアプリケーションに渡らない（鍵ファイルは別途安全に保管済みとする）
openssl req -new -key server.key -subj "/" \
    -addext "subjectAltName=DNS:example.com,DNS:www.example.com" -out server.csr

# PKCS#11 経由で HSM 内の鍵を使う場合（鍵はエクスポートされない）
openssl req -new -engine pkcs11 -keyform engine -key "pkcs11:object=tls-key" -subj "/" \
    -addext "subjectAltName=DNS:example.com" -out server.csr
```

`-subj "/"` で Subject を空にしているのは、CN が SAN に含まれない CSR を Boulder が拒否するため。

---

## 4. 変更対象ファイル

| ファイル | 変更内容 | フェーズ |
| --- | --- | --- |
| `src/types.rs` | `Csr<'a>` 型の定義、`CsrError`、`Error` への variant 追加 | 1, 2 |
| `src/order.rs` | `finalize_with()` と `Order::validate_csr()` の追加、`finalize_csr()` を薄いラッパ化、doc コメントに CSR 経路の説明追加 | 1, 2 |
| `src/lib.rs` | `pub use types::{Csr, CsrError}` の追加 | 1 |
| `Cargo.toml` | `rustls-pki-types` の最低バージョン引き上げと `features = ["std"]` の明示、`rcgen/...` → `rcgen?/...` の修正、`aws-lc-rs`/`ring` feature から `x509-parser?/verify-aws`・`x509-parser?/verify` への伝播、新 example の登録 | 1, 2 |
| `examples/provision_csr.rs`（新規） | `--csr <path>` を受け取り、鍵に一切触らず発行するサンプル | 3 |
| `examples/csr_external_key.rs`（新規・任意） | rcgen の `SigningKey` を外部実装するサンプル（ダミー署名器で可） | 3 |
| `tests/pebble.rs` | 外部 CSR 経路の統合テストを追加 | 1, 2 |
| `tests/testdata/` | 固定の CSR フィクスチャ（正常・SAN 不一致・CN 不整合・アカウント鍵再利用）を追加 | 2 |
| `README.md` | Features / Cargo features / 使い方に CSR 経路を追記 | 1〜3 |
| `docs/`（本書） | 実装に合わせて更新 | 全体 |

---

## 5. 実装ステップ

### PR 1: CSR 入力の型付け（フェーズ 1）

- [ ] `Csr<'a>` を実装（`from_der` / `from_pem` / `from_pem_file` / `der`）
- [ ] `Order::finalize_with(&mut self, csr: &Csr<'_>)` を追加、`finalize_csr` をラッパ化
- [ ] `Cargo.toml` の `rustls-pki-types` を `CertificateSigningRequestDer` が入るバージョン以上に引き上げ、**`features = ["std"]` を明示**（`from_pem_file` のため。他クレート経由の `std` 有効化に依存しない）
- [ ] `Cargo.toml` の `aws-lc-rs` / `ring` feature を `rcgen/...` から **`rcgen?/...`** に修正（optional な `rcgen` を巻き込まないようにする）
- [ ] `cargo check-external-types` が通ることを確認（`rustls_pki_types::*` は許可済み）
- [ ] PEM 入力の unit テスト（固定フィクスチャの PEM をデコードした結果が、対応する DER フィクスチャと一致すること）
- [ ] feature 組み合わせのビルド確認
  - `--no-default-features --features aws-lc-rs`（HTTP クライアント持ち込み。`std` 明示が効いているかの確認を兼ねる）
  - `--no-default-features --features hyper-rustls,aws-lc-rs`（`cargo tree -e features | grep rcgen` が空になること。修正前は `rcgen v0.14.7` が入る）

### PR 2: 検証（フェーズ 2）

- [ ] `CsrError` と `Order::validate_csr()` / `Csr::validate(&[AuthorizedIdentifier])` を実装（`x509-parser` feature）、`Error::Csr` variant を追加
- [ ] SAN カバレッジ / 余剰 SAN / CN 整合 / アカウント鍵再利用 / 署名検証
- [ ] `Cargo.toml` の feature 伝播（`aws-lc-rs = [..., "x509-parser?/verify-aws"]`、`ring = [..., "x509-parser?/verify"]`）
- [ ] フィクスチャベースの unit テスト（正常系 + 不正系 4 種）
- [ ] ワイルドカード（`*.example.com`）と IPv6 identifier の比較テスト

### PR 3: サンプルとドキュメント（フェーズ 3）

- [ ] `examples/provision_csr.rs`
- [ ] `README.md` の Features に「外部生成 CSR / 外部保管鍵での発行」を追記、Cargo features 節を更新
- [ ] `Order::finalize_csr` / `finalize_with` の rustdoc に、鍵を渡さない運用の説明と OpenSSL コマンド例を追加
- [ ] `tests/pebble.rs` に外部 CSR 経路の統合テスト（`#[ignore]` 付き、既存テストと同じ運用）

上流（djc/instant-acme）への提出はこの 3 分割が妥当。PR 1 だけでも単体で価値があり、レビューしやすい。PR 2 は「検証を暗黙にするか明示にするか」で議論になりうるので、Issue で方針合意を取ってから出す。

---

## 6. テスト計画

### Unit（新規依存なしで実行可能）

| ケース | 期待 |
| --- | --- |
| PEM フィクスチャのデコード結果 == DER フィクスチャ | 一致（`Csr` に PEM 出力は持たせないのでラウンドトリップではなく片道で検証する） |
| ゴミ PEM / 空ファイル / ラベル違い（`PRIVATE KEY`） | `Error` を返す（panic しない） |
| SAN がオーダーと一致 | `Ok` |
| SAN が identifier を欠く | `CsrError::MissingIdentifier` |
| SAN にオーダー外の名前 | `CsrError::UnexpectedIdentifier` |
| CN が SAN に無い | `CsrError::CommonNameNotInSan` |
| CSR の公開鍵 == アカウント鍵 | `CsrError::AccountKeyReuse`（`Order::validate_csr()` 経由。`Csr::validate()` では検査しない） |
| 署名が壊れた CSR | `CsrError::BadSignature`（`verify` feature 有効時） |
| `*.example.com` のワイルドカード | オーダーの `wildcard` ビットと整合 |
| `2001:db8::1` vs `2001:0db8:0:0:0:0:0:1` | 同一と判定 |

### 統合（pebble、既存の `#[ignore]` 運用に従う）

- 外部で生成した CSR（テスト内では rcgen で作るが、鍵は instant-acme に渡さない）で `finalize_with` → `poll_certificate` が成功する。
- 発行された証明書の SAN が CSR の SAN と一致する（`x509-parser` で確認）。
- SAN 不一致の CSR を `validate()` が事前に弾き、ACME 往復が発生しないこと。
- `rcgen` feature を無効にしたビルドで、固定フィクスチャ CSR を使って発行が完走すること。

---

## 7. 互換性・リリース

- **semver**: 案 C を採る限りすべて純粋な追加。`Error` は既に `#[non_exhaustive]`（`src/types.rs:23-26`）なので `Error::Csr` の追加も非破壊。ただし `rcgen/...` → `rcgen?/...` の修正は、これまで暗黙に `rcgen` が有効化されていたことに依存していた下流をビルドエラーにしうる（`Order::finalize()` が消える）。0.10.0 に含めるか、CHANGELOG で明示する。
- **MSRV**: 現在 1.85。新しい言語機能は不要なので据え置き。
- **依存**: 新規クレートの追加なし。`rustls-pki-types` の最低バージョン引き上げと `std` feature の明示のみ。`std` は既定構成では他クレート経由で有効になっているため、実質的な増分は無い。
- **feature 表**（更新後の想定）

  | feature | CSR 経路への影響 |
  | --- | --- |
  | （なし） | `Csr::from_der` / `from_pem` / `finalize_with` が使える。**`rcgen?/...` への修正後は**鍵生成コードがリンクされない |
  | `x509-parser` | `Order::validate_csr()` / `Csr::validate()` が使える |
  | `x509-parser` + `aws-lc-rs` / `ring` | 上記に加えて CSR 署名検証が有効 |
  | `rcgen` + バックエンド | 従来どおり `Order::finalize()` による鍵自動生成も使える |

---

## 8. リスクと未決事項

1. **検証を暗黙にするか明示にするか** — 本書は明示（`Order::validate_csr()` を呼ぶのは利用者）を推奨。feature unification による挙動変化を避けるため。上流の意見次第では、`finalize_with` に `CsrPolicy` 引数を持たせる案（デフォルトで検証あり、feature 無効時はコンパイルエラーではなく検証スキップ）も検討余地あり。
2. **余剰 SAN の扱い** — CA によって挙動が違う（Boulder は identifier と SAN の完全一致を要求、他の CA は緩い）。デフォルトを厳格にすると一部 CA で使えなくなる可能性があるため、緩和オプションを最初から用意する。
3. **`rustls-pki-types` の `CertificateSigningRequestDer` 導入バージョン** — 1.12.0 に存在することは手元のソースで確認済み。それ以前のどこで入ったかは crates.io で確認して最低バージョンを決める。必要以上に上げると下流の解決に影響する。
4. **`x509-parser` の `verify` feature が `ring` を引き込む** — instant-acme が `aws-lc-rs` のみ構成のとき、誤って `verify`（ring 版）を有効にすると ring が余計にリンクされる。feature マッピングを間違えないこと。テストで `cargo tree` を確認する。なお両方有効でも `verify-aws` が優先されるためビルドは壊れない。
5. **rcgen の同期 `sign` と非同期 KMS** — 本体の課題ではないがユーザが必ず踏む。サンプルに `spawn_blocking` パターンを含める。ここを避けたい場合は「CSR は別プロセス/別ツールで作る」ことを推奨経路として提示する。
6. **`Order::finalize()` の非推奨化** — 鍵を返す API はメモリ上に秘密鍵を載せるため、CSR 経路が整った後は「テスト・デモ向け」と位置づけを明記したい。ただし既存利用者が多いはずなので削除はしない。ドキュメントでの誘導に留める。
7. **`rcgen?/...` への変更の是非** — 「`aws-lc-rs` を有効にすると `rcgen` も有効になる」現状の挙動は、`Order::finalize()` を常に使えるようにする意図的な設計かもしれない。上流に出す前に Issue で意図を確認する。少なくとも当リポジトリ（seera-networks fork）では鍵生成コードを含めない構成を取れるようにしたい。

---

## 9. 参考

- RFC 8555 §7.4（finalize と CSR の要件）、§11.1（アカウント鍵を証明書鍵に流用しないこと）
- RFC 2986（PKCS#10）
- Boulder の CSR 検証実装（SAN 数上限、CN と SAN の関係、弱鍵拒否）
- 本リポジトリ: `src/order.rs:65`, `src/order.rs:90`, `src/types.rs:243`, `src/crypto.rs:80`
