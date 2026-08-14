//! Build a CSR for a key instant-acme never sees, using an external signer.
//!
//! The key here is loaded into an aws-lc-rs `EcdsaKeyPair` so that the example runs on its own,
//! but it is only ever reached through [`rcgen::SigningKey`] — swap the two method bodies for
//! calls into your HSM or KMS, drop the `--key` argument, and nothing else changes. Feed the
//! resulting CSR to [`Order::finalize_with()`][instant_acme::Order::finalize_with()]; see
//! `provision_csr.rs`.
//!
//! The key is yours to keep: the certificate you get back is only usable with it, so generate
//! it somewhere it will survive.
//!
//! ```sh
//! openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server.key
//!
//! cargo run --example csr_external_key -- --key server.key \
//!     --names example.com --names www.example.com > server.csr
//! ```

use std::path::{Path, PathBuf};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use clap::Parser;
use rcgen::{CertificateParams, DistinguishedName, PublicKeyData, SignatureAlgorithm, SigningKey};
use rustls_pki_types::PrivatePkcs8KeyDer;
use rustls_pki_types::pem::PemObject;

fn main() -> anyhow::Result<()> {
    let opts = Options::parse();
    let key = RemoteKey::new(&opts.key)?;

    let mut params = CertificateParams::new(opts.names)?;
    // An ACME CA fills in the subject itself, and a common name that is not also a
    // subjectAltName gets the CSR rejected outright, so leave the subject empty.
    params.distinguished_name = DistinguishedName::new();

    let csr = params.serialize_request(&key)?;
    println!("{}", csr.pem()?);
    Ok(())
}

/// A signer for a key held somewhere this process cannot read it
struct RemoteKey {
    key_pair: EcdsaKeyPair,
    /// The public key, as the uncompressed EC point `0x04 || X || Y`
    public_key: Vec<u8>,
}

impl RemoteKey {
    fn new(path: &Path) -> anyhow::Result<Self> {
        // Stands in for "open a session and look up the key by handle". Reading the key from a
        // file is the part you would not do for real: the point of this trait implementation is
        // that everything below works the same when the key cannot be read at all.
        let pkcs8 = PrivatePkcs8KeyDer::from_pem_file(path)
            .map_err(|err| anyhow::anyhow!("failed to read {}: {err}", path.display()))?;
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.secret_pkcs8_der())
                .map_err(|_| anyhow::anyhow!("not a PKCS#8 P-256 private key"))?;

        // NOTE: this is the EC point, not a SubjectPublicKeyInfo. A KMS `GetPublicKey` call
        // hands you a full SPKI, and rcgen wraps whatever it gets in another one: pass the
        // SPKI straight through and you produce a CSR no CA will accept. Unwrap it first.
        let public_key = key_pair.public_key().as_ref().to_vec();
        Ok(Self {
            key_pair,
            public_key,
        })
    }
}

impl PublicKeyData for RemoteKey {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl SigningKey for RemoteKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        // `msg` is the message to sign, not a digest: hash it yourself if your KMS takes one.
        //
        // Two things to watch for with a remote signer:
        //
        // * This method is synchronous. Calling an async KMS client from here needs
        //   `tokio::task::block_in_place()` (multi-threaded runtime only), or run the whole
        //   CSR construction under `tokio::task::spawn_blocking()`. Do not `block_on()` a
        //   handle for the runtime you are already on: that deadlocks.
        // * The signature must be ASN.1 DER (`SEQUENCE { r INTEGER, s INTEGER }`). AWS KMS
        //   returns that; an HSM handing back a raw `r || s` pair needs converting.
        let signature = self
            .key_pair
            .sign(&SystemRandom::new(), msg)
            .map_err(|_| rcgen::Error::RingUnspecified)?;

        Ok(signature.as_ref().to_vec())
    }
}

#[derive(Parser)]
struct Options {
    /// Path to the PKCS#8 PEM private key to sign the request with
    ///
    /// Stands in for a key held by an HSM or KMS; keep it, the certificate needs it.
    #[clap(long)]
    key: PathBuf,
    /// The DNS names to request a certificate for
    #[clap(long, required = true)]
    names: Vec<String>,
}
