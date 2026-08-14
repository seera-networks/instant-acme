#![cfg(any(feature = "ring", feature = "aws-lc-rs"))]
//! Issue a certificate for a CSR made elsewhere, without ever holding the private key.
//!
//! Unlike `provision.rs`, this never asks instant-acme to generate a key: the CSR arrives as a
//! file, and the key behind it can stay in an HSM, a KMS, or a file this process cannot read.
//! Produce the CSR with `csr_external_key.rs`, or with openssl:
//!
//! ```sh
//! openssl req -new -key server.key -subj "/" \
//!     -addext "subjectAltName=DNS:example.com,DNS:www.example.com" -out server.csr
//! ```
//!
//! Then, with the names matching the CSR's subjectAltName values:
//!
//! ```sh
//! cargo run --features x509-parser --example provision_csr -- \
//!     --names example.com --names www.example.com --csr server.csr
//! ```
//!
//! The `x509-parser` feature is what enables the pre-flight check of the CSR against the order.
//! It is worth having: without it, a CSR that does not match the names is only rejected once
//! the challenges have been solved, and the order is spent by then.
//!
//! `--directory` and `--ca-cert` point it at another CA, such as a local Pebble:
//!
//! ```sh
//! cargo run --features x509-parser --example provision_csr -- \
//!     --names example.com --csr server.csr \
//!     --directory https://127.0.0.1:14000/dir --ca-cert tests/testdata/ca.pem
//! ```

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, CryptoProvider, Csr, DefaultClient, Identifier,
    LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let opts = Options::parse();

    // The CSR is just bytes to us: we never see the key that signed it.
    let csr = Csr::from_pem_file(&opts.csr)?;

    #[cfg(feature = "aws-lc-rs")]
    let (provider, rustls_crypto_provider) = (
        CryptoProvider::aws_lc_rs(),
        rustls::crypto::aws_lc_rs::default_provider(),
    );

    #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
    let (provider, rustls_crypto_provider) = (
        CryptoProvider::ring(),
        rustls::crypto::ring::default_provider(),
    );

    // Point `--ca-cert` at the test PKI's root when talking to a CA like Pebble.
    let rustls_crypto_provider = Arc::new(rustls_crypto_provider);
    let http = match &opts.ca_cert {
        Some(path) => DefaultClient::with_pem_root(path, rustls_crypto_provider)?,
        None => DefaultClient::new(rustls_crypto_provider)?,
    };

    let directory = opts
        .directory
        .clone()
        .unwrap_or_else(|| LetsEncrypt::Staging.url().to_owned());

    let (account, credentials) = Account::builder(Box::new(http), provider)?
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory,
            None,
        )
        .await?;
    info!(
        "account credentials:\n\n{}",
        serde_json::to_string_pretty(&credentials)?
    );

    let identifiers = opts
        .names
        .iter()
        .map(|ident| Identifier::Dns(ident.clone()))
        .collect::<Vec<_>>();
    let mut order = account
        .new_order(&NewOrder::new(identifiers.as_slice()))
        .await?;

    // Catch a CSR that does not match this order before spending the order on it.
    #[cfg(feature = "x509-parser")]
    order.validate_csr(&csr).await?;

    // Built without `--features x509-parser`, so a mismatch between `--names` and the CSR will
    // only surface as a `badCSR` problem at finalization, after the challenges are solved.
    #[cfg(not(feature = "x509-parser"))]
    tracing::warn!("built without the `x509-parser` feature: not checking the CSR up front");

    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = result?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            _ => todo!(),
        }

        let mut challenge = authz
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| anyhow::anyhow!("no dns01 challenge found"))?;

        println!("Please set the following DNS record then press the Return key:");
        println!(
            "_acme-challenge.{} IN TXT {}",
            challenge.identifier(),
            challenge.key_authorization()?.dns_value()
        );
        io::stdin().read_line(&mut String::new())?;

        challenge.set_ready().await?;
    }

    let status = order.poll_ready(&RetryPolicy::default()).await?;
    if status != OrderStatus::Ready {
        return Err(anyhow::anyhow!("unexpected order status: {status:?}"));
    }

    order.finalize_with(&csr).await?;
    let cert_chain_pem = order.poll_certificate(&RetryPolicy::default()).await?;

    // Note what is missing here compared to `provision.rs`: there is no private key to print,
    // because this process never had one.
    info!("certificate chain:\n\n{cert_chain_pem}");
    Ok(())
}

#[derive(Parser)]
struct Options {
    /// The DNS names to request a certificate for, matching the CSR's subjectAltName values
    #[clap(long, required = true)]
    names: Vec<String>,
    /// Path to a PEM-encoded PKCS#10 certificate signing request
    #[clap(long)]
    csr: PathBuf,
    /// ACME directory URL (defaults to the Let's Encrypt staging environment)
    #[clap(long)]
    directory: Option<String>,
    /// PEM-encoded root certificate to trust, for a CA using a test PKI
    #[clap(long)]
    ca_cert: Option<PathBuf>,
}
