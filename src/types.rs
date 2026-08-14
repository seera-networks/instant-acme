use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::{self, Write};
use std::net::IpAddr;
use std::time::Instant;

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, CertificateSigningRequestDer, Der, PrivatePkcs8KeyDer};
use serde::de::{self, DeserializeOwned};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "time")]
use time::OffsetDateTime;
#[cfg(feature = "x509-parser")]
use x509_parser::certification_request::X509CertificationRequest;
#[cfg(feature = "x509-parser")]
use x509_parser::extensions::{GeneralName, ParsedExtension};
#[cfg(feature = "x509-parser")]
use x509_parser::parse_x509_certificate;
#[cfg(feature = "x509-parser")]
use x509_parser::prelude::FromDer;
#[cfg(feature = "x509-parser")]
use x509_parser::public_key::PublicKey;

use crate::{BytesResponse, Sha256};

/// Error type for instant-acme
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// An JSON problem as returned by the ACME server
    ///
    /// RFC 8555 uses problem documents as described in RFC 7807.
    #[error(transparent)]
    Api(#[from] Problem),
    /// Failed from cryptographic operations
    #[error("cryptographic operation failed")]
    Crypto,
    /// A CSR does not match the order it was passed for
    #[cfg(feature = "x509-parser")]
    #[cfg_attr(instant_acme_docsrs, doc(cfg(feature = "x509-parser")))]
    #[error(transparent)]
    Csr(#[from] CsrError),
    /// Failed to instantiate a private key
    #[error("invalid key bytes")]
    KeyRejected,
    /// HTTP failure
    #[error("HTTP request failure: {0}")]
    Http(#[from] http::Error),
    /// Hyper request failure
    #[cfg(feature = "hyper-rustls")]
    #[error("HTTP request failure: {0}")]
    Hyper(#[from] hyper::Error),
    /// Invalid ACME server URL
    #[error("invalid URI: {0}")]
    InvalidUri(#[from] http::uri::InvalidUri),
    /// Failed to (de)serialize a JSON object
    #[error("failed to (de)serialize JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Failed to decode PEM input
    ///
    /// Not marked as the error's `source`: `rustls_pki_types::pem::Error` only implements
    /// `std::error::Error` when its `std` feature is enabled, which is what our `fs` feature
    /// turns on.
    #[error("failed to decode PEM: {0}")]
    Pem(rustls_pki_types::pem::Error),
    /// Timed out while waiting for the server to update [`OrderStatus`]
    ///
    /// If `Some`, the nested `Instant` indicates when the server suggests to poll next.
    #[error("timed out waiting for an order update")]
    Timeout(Option<Instant>),
    /// ACME server does not support a requested feature
    #[error("ACME server does not support: {0}")]
    Unsupported(&'static str),
    /// Other kind of error
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// Miscellaneous errors
    #[error("missing data: {0}")]
    Str(&'static str),
}

impl Error {
    #[cfg(all(feature = "rcgen", any(feature = "aws-lc-rs", feature = "ring")))]
    pub(crate) fn from_rcgen(err: rcgen::Error) -> Self {
        Self::Other(Box::new(err))
    }
}

impl From<&'static str> for Error {
    fn from(s: &'static str) -> Self {
        Self::Str(s)
    }
}

impl From<rustls_pki_types::pem::Error> for Error {
    fn from(err: rustls_pki_types::pem::Error) -> Self {
        Self::Pem(err)
    }
}

/// ACME account credentials
///
/// This opaque type contains the account ID, the private key data and the
/// server URLs from the relevant ACME server. This can be used to serialize
/// the account credentials to a file or secret manager and restore the
/// account from persistent storage.
#[must_use]
#[derive(Deserialize, Serialize)]
pub struct AccountCredentials {
    pub(crate) id: String,
    /// Stored in DER, serialized as base64
    #[serde(with = "pkcs8_serde")]
    pub(crate) key_pkcs8: PrivatePkcs8KeyDer<'static>,
    pub(crate) directory: Option<String>,
    /// We never serialize `urls` by default, but we support deserializing them
    /// in order to support serialized data from older versions of the library.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) urls: Option<Directory>,
}

impl AccountCredentials {
    /// The account's private key
    pub fn private_key(&self) -> &PrivatePkcs8KeyDer<'_> {
        &self.key_pkcs8
    }
}

mod pkcs8_serde {
    use std::fmt;

    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
    use rustls_pki_types::PrivatePkcs8KeyDer;
    use serde::{Deserializer, Serializer, de};

    pub(crate) fn serialize<S: Serializer>(
        key_pkcs8: &PrivatePkcs8KeyDer<'_>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(key_pkcs8.secret_pkcs8_der());
        serializer.serialize_str(&encoded)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<PrivatePkcs8KeyDer<'static>, D::Error> {
        struct Visitor;

        impl de::Visitor<'_> for Visitor {
            type Value = PrivatePkcs8KeyDer<'static>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a base64-encoded PKCS#8 private key")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                match BASE64_URL_SAFE_NO_PAD.decode(v) {
                    Ok(bytes) => Ok(PrivatePkcs8KeyDer::from(bytes)),
                    Err(err) => Err(de::Error::custom(err)),
                }
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

/// An RFC 7807 problem document as returned by the ACME server
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    /// One of an enumerated list of problem types
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc8555#section-6.7>
    pub r#type: Option<String>,
    /// A human-readable explanation of the problem
    pub detail: Option<String>,
    /// The HTTP status code returned for this response
    pub status: Option<u16>,
    /// One or more subproblems associated with specific identifiers
    ///
    /// See <https://www.rfc-editor.org/rfc/rfc8555#section-6.7.1>
    #[serde(default)]
    pub subproblems: Vec<Subproblem>,
}

impl Problem {
    pub(crate) async fn check<T: DeserializeOwned>(rsp: BytesResponse) -> Result<T, Error> {
        Ok(serde_json::from_slice(&Self::from_response(rsp).await?)?)
    }

    pub(crate) async fn from_response(rsp: BytesResponse) -> Result<Bytes, Error> {
        let status = rsp.parts.status;
        let body = rsp.body().await.map_err(Error::Other)?;
        match status.is_informational() || status.is_success() || status.is_redirection() {
            true => Ok(body),
            false => Err(serde_json::from_slice::<Self>(&body)?.into()),
        }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("API error")?;
        if let Some(detail) = &self.detail {
            write!(f, ": {detail}")?;
        }

        if let Some(r#type) = &self.r#type {
            write!(f, " ({type})")?;
        }

        if !self.subproblems.is_empty() {
            let count = self.subproblems.len();
            write!(f, ": {count} subproblems: ")?;
            for (i, subproblem) in self.subproblems.iter().enumerate() {
                write!(f, "{subproblem}")?;
                if i != count - 1 {
                    f.write_str(", ")?;
                }
            }
        }

        Ok(())
    }
}

impl std::error::Error for Problem {}

/// An RFC 8555 subproblem document contained within a problem returned by the ACME server
///
/// See <https://www.rfc-editor.org/rfc/rfc8555#section-6.7.1>
#[derive(Clone, Debug, Deserialize)]
pub struct Subproblem {
    /// The identifier associated with this problem
    pub identifier: Option<Identifier>,
    /// One of an enumerated list of problem types
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc8555#section-6.7>
    pub r#type: Option<String>,
    /// A human-readable explanation of the problem
    pub detail: Option<String>,
}

impl fmt::Display for Subproblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(identifier) = &self.identifier {
            write!(f, r#"for "{}""#, identifier.authorized(false))?;
        }

        if let Some(detail) = &self.detail {
            write!(f, ": {detail}")?;
        }

        if let Some(r#type) = &self.r#type {
            write!(f, " ({type})")?;
        }

        Ok(())
    }
}

/// A PKCS#10 Certificate Signing Request (CSR) as described in RFC 2986
///
/// Pass one of these to [`Order::finalize_with()`][crate::Order::finalize_with()] to request
/// a certificate for a key pair that instant-acme never gets to see. This is the API to use
/// if your private key lives in an HSM, a KMS, or a file that should not be read into the
/// process: generate the CSR wherever the key lives, then hand the result over.
///
/// The CSR must carry a subjectAltName extension covering every identifier in the order
/// (see RFC 8555 section 7.4), and its key must not be the account key (section 11.1).
///
/// ```no_run
/// # use instant_acme::{Csr, Error};
/// # fn main() -> Result<(), Error> {
/// let csr = Csr::from_pem(b"-----BEGIN CERTIFICATE REQUEST-----\n...")?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Csr<'a>(CertificateSigningRequestDer<'a>);

impl<'a> Csr<'a> {
    /// Use a CSR that is already in DER encoding
    pub fn from_der(der: impl Into<CertificateSigningRequestDer<'a>>) -> Self {
        Self(der.into())
    }

    /// Decode a PEM-encoded CSR (a `CERTIFICATE REQUEST` section)
    ///
    /// Only the first `CERTIFICATE REQUEST` section is used; other sections are ignored.
    pub fn from_pem(pem: &[u8]) -> Result<Csr<'static>, Error> {
        Ok(Csr(CertificateSigningRequestDer::from_pem_slice(pem)?))
    }

    /// Read a PEM-encoded CSR from the file at `path`
    ///
    /// See [`Csr::from_pem()`] for the details of the decoding.
    #[cfg(feature = "fs")]
    #[cfg_attr(instant_acme_docsrs, doc(cfg(feature = "fs")))]
    pub fn from_pem_file(path: impl AsRef<std::path::Path>) -> Result<Csr<'static>, Error> {
        Ok(Csr(CertificateSigningRequestDer::from_pem_file(path)?))
    }

    /// Check this CSR against an order's identifiers, with the default [`CsrPolicy`]
    ///
    /// This is what [`Order::validate_csr()`][crate::Order::validate_csr()] uses; prefer that
    /// method, which also has access to the order's wildcard bits and to the account key.
    /// Use this one to check a CSR before you have an order, or in an offline tool.
    #[cfg(feature = "x509-parser")]
    #[cfg_attr(instant_acme_docsrs, doc(cfg(feature = "x509-parser")))]
    pub fn validate(&self, identifiers: &[AuthorizedIdentifier<'_>]) -> Result<(), CsrError> {
        self.validate_with(identifiers, &CsrPolicy::default())
    }

    /// Check this CSR against an order's identifiers, with the given [`CsrPolicy`]
    ///
    /// Nothing here talks to the ACME server: this is the same set of checks a CA applies,
    /// run locally, so that a mismatch costs you a helpful error instead of a failed
    /// finalization (and one of your rate-limited orders).
    #[cfg(feature = "x509-parser")]
    #[cfg_attr(instant_acme_docsrs, doc(cfg(feature = "x509-parser")))]
    pub fn validate_with(
        &self,
        identifiers: &[AuthorizedIdentifier<'_>],
        policy: &CsrPolicy,
    ) -> Result<(), CsrError> {
        let request = self.parse()?;

        // The names the order authorizes us to ask for. Attestation identifiers are not
        // expressed as subjectAltName values we could compare, so we skip them here.
        let (mut wanted_dns, mut wanted_ips) = (Vec::new(), Vec::new());
        for identifier in identifiers {
            match (identifier.identifier, identifier.wildcard) {
                (Identifier::Dns(name), true) => {
                    wanted_dns.push(format!("*.{}", name.to_ascii_lowercase()))
                }
                (Identifier::Dns(name), false) => wanted_dns.push(name.to_ascii_lowercase()),
                (Identifier::Ip(addr), _) => wanted_ips.push(*addr),
                _ => {}
            }
        }

        // The names the CSR asks for.
        let (mut dns, mut ips, mut has_san) = (Vec::new(), Vec::new(), false);
        for extension in request.requested_extensions().into_iter().flatten() {
            let ParsedExtension::SubjectAlternativeName(san) = extension else {
                continue;
            };

            has_san = true;
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(name) => dns.push(name.to_ascii_lowercase()),
                    GeneralName::IPAddress(bytes) => ips.push(match <[u8; 4]>::try_from(*bytes) {
                        Ok(octets) => IpAddr::from(octets),
                        Err(_) => match <[u8; 16]>::try_from(*bytes) {
                            Ok(octets) => IpAddr::from(octets),
                            Err(_) => {
                                return Err(CsrError::Parse(
                                    "invalid IP address in subjectAltName",
                                ));
                            }
                        },
                    }),
                    // Other name types are not something an ACME order authorizes.
                    _ => {}
                }
            }
        }

        if !has_san && !(wanted_dns.is_empty() && wanted_ips.is_empty()) {
            return Err(CsrError::NoSubjectAltName);
        }

        for name in &wanted_dns {
            if !dns.contains(name) {
                return Err(CsrError::MissingIdentifier(name.clone()));
            }
        }

        for addr in &wanted_ips {
            if !ips.contains(addr) {
                return Err(CsrError::MissingIdentifier(addr.to_string()));
            }
        }

        if !policy.allow_extra_identifiers {
            for name in &dns {
                if !wanted_dns.contains(name) {
                    return Err(CsrError::UnexpectedIdentifier(name.clone()));
                }
            }

            for addr in &ips {
                if !wanted_ips.contains(addr) {
                    return Err(CsrError::UnexpectedIdentifier(addr.to_string()));
                }
            }
        }

        // A subject common name that is not also a subjectAltName gets the CSR rejected by
        // (at least) Boulder, so catch it here rather than at finalization.
        for attribute in request
            .certification_request_info
            .subject
            .iter_common_name()
        {
            let name = attribute
                .as_str()
                .map_err(|_| CsrError::Parse("subject common name is not a string"))?;
            let lowercase = name.to_ascii_lowercase();
            if !dns.contains(&lowercase) && !ips.iter().any(|addr| addr.to_string() == name) {
                return Err(CsrError::CommonNameNotInSan(name.to_owned()));
            }
        }

        // Requires x509-parser's `verify`/`verify-aws` feature, which our backend features
        // turn on for us.
        #[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
        request
            .verify_signature()
            .map_err(|_| CsrError::BadSignature)?;

        Ok(())
    }

    /// Yield an error if this CSR's public key is the given account key (RFC 8555 section 11.1)
    #[cfg(feature = "x509-parser")]
    pub(crate) fn check_account_key(&self, key: &crate::Key) -> Result<(), CsrError> {
        let request = self.parse()?;
        let spki = &request.certification_request_info.subject_pki;
        let same = match (key.inner.as_jwk().key, spki.parsed()) {
            (JwkThumbFields::Ec { x, y, .. }, Ok(PublicKey::EC(point))) => {
                // An uncompressed EC point: 0x04 || X || Y.
                let point = point.data();
                point.len() == 1 + x.len() + y.len()
                    && point[0] == 0x04
                    && &point[1..1 + x.len()] == x
                    && &point[1 + x.len()..] == y
            }
            // Ed25519 and friends: the key is the bit string, with no further structure.
            (JwkThumbFields::Okp { x, .. }, _) => spki.subject_public_key.data.as_ref() == x,
            (JwkThumbFields::Rsa { e, n }, Ok(PublicKey::RSA(rsa))) => {
                trim_leading_zeros(rsa.modulus) == trim_leading_zeros(n)
                    && trim_leading_zeros(rsa.exponent) == trim_leading_zeros(e)
            }
            _ => false,
        };

        match same {
            true => Err(CsrError::AccountKeyReuse),
            false => Ok(()),
        }
    }

    #[cfg(feature = "x509-parser")]
    fn parse(&self) -> Result<X509CertificationRequest<'_>, CsrError> {
        let (rest, request) = X509CertificationRequest::from_der(self.der())
            .map_err(|_| CsrError::Parse("not a valid PKCS#10 certification request"))?;

        match rest.is_empty() {
            true => Ok(request),
            false => Err(CsrError::Parse(
                "trailing data after the certification request",
            )),
        }
    }

    /// The DER encoding of the CSR
    pub fn der(&self) -> &[u8] {
        &self.0
    }
}

/// How strictly a CSR is checked against an order
///
/// Used by [`Csr::validate_with()`] and
/// [`Order::validate_csr_with()`][crate::Order::validate_csr_with()].
#[cfg(feature = "x509-parser")]
#[cfg_attr(instant_acme_docsrs, doc(cfg(feature = "x509-parser")))]
#[derive(Clone, Debug, Default)]
pub struct CsrPolicy {
    allow_extra_identifiers: bool,
}

#[cfg(feature = "x509-parser")]
impl CsrPolicy {
    /// A `CsrPolicy` that requires the CSR's names to match the order's identifiers exactly
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept a CSR that asks for names the order does not cover
    ///
    /// Off by default, because an ACME server will not issue for identifiers you have no
    /// authorization for: Boulder, for one, rejects the CSR outright. Turn it on for servers
    /// that are known to ignore the extra names instead.
    pub fn allow_extra_identifiers(mut self, allow: bool) -> Self {
        self.allow_extra_identifiers = allow;
        self
    }
}

/// The ways a CSR can fail to match an order
#[cfg(feature = "x509-parser")]
#[cfg_attr(instant_acme_docsrs, doc(cfg(feature = "x509-parser")))]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CsrError {
    /// The CSR's public key is the ACME account key
    ///
    /// <https://www.rfc-editor.org/rfc/rfc8555#section-11.1>
    #[error("the CSR's public key is the ACME account key")]
    AccountKeyReuse,
    /// The CSR's signature does not verify against the key in the CSR
    #[error("the CSR's signature does not verify")]
    BadSignature,
    /// The CSR has a subject common name that is not among its subjectAltName values
    #[error("common name `{0}` is missing from the CSR's subjectAltName extension")]
    CommonNameNotInSan(String),
    /// The order has an identifier that the CSR does not ask for
    #[error("the CSR does not cover identifier `{0}`")]
    MissingIdentifier(String),
    /// The CSR has no subjectAltName extension, but the order has identifiers
    #[error("the CSR has no subjectAltName extension")]
    NoSubjectAltName,
    /// The CSR could not be parsed
    #[error("failed to parse the CSR: {0}")]
    Parse(&'static str),
    /// The CSR asks for a name that the order does not authorize
    ///
    /// See [`CsrPolicy::allow_extra_identifiers()`] to allow this.
    #[error("the CSR asks for identifier `{0}`, which the order does not authorize")]
    UnexpectedIdentifier(String),
}

/// Compare integers that may or may not carry a leading zero byte
#[cfg(feature = "x509-parser")]
fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
    &bytes[zeros..]
}

impl<'a> From<&'a [u8]> for Csr<'a> {
    fn from(der: &'a [u8]) -> Self {
        Self(der.into())
    }
}

impl From<Vec<u8>> for Csr<'_> {
    fn from(der: Vec<u8>) -> Self {
        Self(der.into())
    }
}

impl<'a> From<CertificateSigningRequestDer<'a>> for Csr<'a> {
    fn from(der: CertificateSigningRequestDer<'a>) -> Self {
        Self(der)
    }
}

/// Borrow a CSR from something that owns its DER encoding
///
/// This exists because `Into<CertificateSigningRequestDer<'_>>` is not implemented for
/// references to it, so `Csr::from_der(csr.der())` would not compile for, say, an
/// `rcgen::CertificateSigningRequest`.
impl<'a> From<&'a CertificateSigningRequestDer<'a>> for Csr<'a> {
    fn from(der: &'a CertificateSigningRequestDer<'a>) -> Self {
        Self(der.as_ref().into())
    }
}

impl AsRef<[u8]> for Csr<'_> {
    fn as_ref(&self) -> &[u8] {
        self.der()
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct FinalizeRequest {
    csr: String,
}

impl FinalizeRequest {
    pub(crate) fn new(csr_der: &[u8]) -> Self {
        Self {
            csr: BASE64_URL_SAFE_NO_PAD.encode(csr_der),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct Header<'a> {
    pub(crate) alg: SigningAlgorithm,
    #[serde(flatten)]
    pub(crate) key: KeyOrKeyId<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) nonce: Option<&'a str>,
    pub(crate) url: &'a str,
}

#[derive(Debug, Serialize)]
pub(crate) enum KeyOrKeyId<'a> {
    #[serde(rename = "jwk")]
    Key(Jwk<'a>),
    #[serde(rename = "kid")]
    KeyId(&'a str),
}

/// A JSON Web Key (JWK) as used in JWS headers
///
/// See [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) for more information.
#[derive(Debug, Serialize)]
pub struct Jwk<'a> {
    /// The algorithm intended for use with this key
    pub alg: SigningAlgorithm,
    /// Key-type-specific parameters
    #[serde(flatten)]
    pub key: JwkThumbFields<'a>,
    /// The intended use (`"sig"` for signing)
    pub r#use: &'static str,
}

impl<'a> Jwk<'a> {
    /// Compute the [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) JWK thumbprint.
    ///
    /// Serializes only the required key-type-specific members in lexicographic order,
    /// then hashes with SHA-256.
    pub(crate) fn thumb_sha256(
        &'a self,
        sha256: &dyn Sha256,
    ) -> Result<[u8; 32], serde_json::Error> {
        Ok(sha256.hash(&serde_json::to_vec(&self.key)?))
    }
}

/// Key-type-specific JWK parameters
///
/// Each variant's fields are declared in lexicographic order for correct
/// [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) thumbprint computation.
#[derive(Debug)]
#[non_exhaustive]
pub enum JwkThumbFields<'a> {
    /// Elliptic Curve key (P-256, P-384, etc.)
    Ec {
        /// The curve name
        crv: EcCurve,
        /// The x coordinate (serialized as base64url)
        x: &'a [u8],
        /// The y coordinate (serialized as base64url)
        y: &'a [u8],
    },
    /// Octet Key Pair (Ed25519, Ed448, X25519, etc.)
    Okp {
        /// The curve name
        crv: OctetKeyCurve,
        /// The public key (serialized as base64url)
        x: &'a [u8],
    },
    /// RSA key
    Rsa {
        /// The public exponent (serialized as base64url)
        e: &'a [u8],
        /// The modulus (serialized as base64url)
        n: &'a [u8],
    },
}

impl Serialize for JwkThumbFields<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Do this manually, because fields must be in lexicographic order for thumbprints.
        // In particular, this means the `kty` tag field must come after `crv` or `e` fields.
        // https://www.rfc-editor.org/rfc/rfc7638#section-3.3
        match self {
            Self::Ec { crv, x, y } => {
                let mut map = serializer.serialize_map(Some(4))?;
                map.serialize_entry("crv", crv)?;
                map.serialize_entry("kty", "EC")?;
                map.serialize_entry("x", &Base64Bytes(x))?;
                map.serialize_entry("y", &Base64Bytes(y))?;
                map.end()
            }
            Self::Okp { crv, x } => {
                let mut map = serializer.serialize_map(Some(3))?;
                map.serialize_entry("crv", crv)?;
                map.serialize_entry("kty", "OKP")?;
                map.serialize_entry("x", &Base64Bytes(x))?;
                map.end()
            }
            Self::Rsa { e, n } => {
                let mut map = serializer.serialize_map(Some(3))?;
                map.serialize_entry("e", &Base64Bytes(e))?;
                map.serialize_entry("kty", "RSA")?;
                map.serialize_entry("n", &Base64Bytes(n))?;
                map.end()
            }
        }
    }
}

struct Base64Bytes<'a>(&'a [u8]);

impl Serialize for Base64Bytes<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&BASE64_URL_SAFE_NO_PAD.encode(self.0))
    }
}

/// Elliptic curve names for EC keys
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub enum EcCurve {
    /// P-256, <https://www.iana.org/go/rfc7518#section-6.2.1.1>
    #[serde(rename = "P-256")]
    P256,
    /// P-384, <https://www.iana.org/go/rfc7518#section-6.2.1.1>
    #[serde(rename = "P-384")]
    P384,
    /// P-521, <https://www.iana.org/go/rfc7518#section-6.2.1.1>
    #[serde(rename = "P-521")]
    P521,
}

/// Elliptic curve names for OKP keys
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub enum OctetKeyCurve {
    /// Ed25519, <https://datatracker.ietf.org/doc/html/rfc8037#section-3.1>
    Ed25519,
    /// Ed448, <https://datatracker.ietf.org/doc/html/rfc8037#section-3.1>
    Ed448,
    /// X25519, <https://datatracker.ietf.org/doc/html/rfc8037#section-3.2>
    X25519,
    /// X448, <https://datatracker.ietf.org/doc/html/rfc8037#section-3.2>
    X448,
}

/// An ACME challenge as described in RFC 8555 (section 7.1.5)
///
/// <https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.5>
#[derive(Debug, Deserialize)]
pub struct Challenge {
    /// Type of challenge
    pub r#type: ChallengeType,
    /// Challenge identifier
    pub url: String,
    /// Token for this challenge
    ///
    /// Unknown `ChallengeType` instances may omit this field, leaving it empty.
    #[serde(default)]
    pub token: String,
    /// Current status
    pub status: ChallengeStatus,
    /// Potential error state
    pub error: Option<Problem>,
}

/// Contents of an ACME order as described in RFC 8555 (section 7.1.3)
///
/// The order identity will usually be represented by an [Order](crate::Order).
///
/// <https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.3>
#[derive(Debug, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "camelCase")]
pub struct OrderState {
    /// Current status
    pub status: OrderStatus,
    /// Authorizations for this order.
    ///
    /// There should be one authorization per identifier in the order.
    ///
    /// Callers will usually interact with an [`AuthorizationHandle`] obtained
    /// via [`Order::authorizations()`] instead of using this directly.
    ///
    /// [`AuthorizationHandle`]: crate::AuthorizationHandle
    /// [`Order::authorizations()`]: crate::Order::authorizations()
    pub authorizations: Vec<Authorization>,
    /// Potential error state
    pub error: Option<Problem>,
    /// A finalization URL, to be used once status becomes `Ready`
    pub finalize: String,
    /// The certificate URL, which becomes available after finalization
    pub certificate: Option<String>,
    /// The certificate that this order is replacing, if any
    #[serde(deserialize_with = "deserialize_static_certificate_identifier")]
    #[serde(default)]
    pub replaces: Option<CertificateIdentifier<'static>>,
    /// The profile to be used for the order
    #[serde(default)]
    pub profile: Option<String>,
}

/// A wrapper for [`AuthorizationState`] as held in the [`OrderState`]
///
/// Callers will usually interact with an [`AuthorizationHandle`] obtained
/// via [`Order::authorizations()`] instead of using this directly.
///
/// [`AuthorizationHandle`]: crate::AuthorizationHandle
/// [`Order::authorizations()`]: crate::Order::authorizations()
#[derive(Debug)]
pub struct Authorization {
    /// URL for this authorization
    pub url: String,
    /// Current state of the authorization
    ///
    /// This starts out as `None` when the [`OrderState`] is first deserialized.
    /// It is populated when the authorization is first fetched from the server,
    /// typically via [`Order::authorizations()`].
    ///
    /// [`Order::authorizations()`]: crate::Order::authorizations()
    pub state: Option<AuthorizationState>,
}

impl<'de> Deserialize<'de> for Authorization {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self {
            url: String::deserialize(deserializer)?,
            state: None,
        })
    }
}

/// Input data for [Order](crate::Order) creation
///
/// To be passed into [Account::new_order()](crate::Account::new_order()).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewOrder<'a> {
    /// The [`CertificateIdentifier`] of a previously issued certificate being replaced by the order
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) replaces: Option<CertificateIdentifier<'a>>,
    /// Identifiers to be included in the order
    identifiers: &'a [Identifier],
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<&'a str>,
}

impl<'a> NewOrder<'a> {
    /// Prepare to create a new order for the given identifiers
    ///
    /// To be passed into [Account::new_order()](crate::Account::new_order()).
    pub fn new(identifiers: &'a [Identifier]) -> Self {
        Self {
            identifiers,
            replaces: None,
            profile: None,
        }
    }

    /// Indicate to the ACME server that the `NewOrder` is replacing a previously issued certificate
    ///
    /// The previously issued certificate must be identified by a `EncodedCertificateIdentifier`.
    ///
    /// Some ACME servers may give preferential rate limits to orders that replace
    /// existing certificates, or use this information to determine when it is safe
    /// to revoke a certificate affected by a compliance incident.
    ///
    /// When provided, at least one of the `identifiers` for the new order must have been
    /// present in the certificate being replaced. If the ACME CA does not support the
    /// ACME renewal information (ARI) extension, the [crate::Account::new_order()] method will
    /// return an error.
    pub fn replaces(mut self, replaces: CertificateIdentifier<'a>) -> Self {
        self.replaces = Some(replaces);
        self
    }

    /// Set the profile to be used for the order
    ///
    /// [`Account::new_order()`][crate::Account::new_order()] will yield an error if the ACME
    /// server does not support the profiles extension or if the specified profile is not
    /// supported.
    pub fn profile(mut self, profile: &'a str) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Identifiers to be included in the order
    pub fn identifiers(&self) -> &[Identifier] {
        self.identifiers
    }
}

/// Payload for a certificate revocation request
/// Defined in <https://datatracker.ietf.org/doc/html/rfc8555#section-7.6>
#[derive(Debug)]
pub struct RevocationRequest<'a> {
    /// The certificate to revoke
    pub certificate: &'a CertificateDer<'a>,
    /// Reason for revocation
    pub reason: Option<RevocationReason>,
}

impl Serialize for RevocationRequest<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let base64 = BASE64_URL_SAFE_NO_PAD.encode(self.certificate);
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("certificate", &base64)?;
        if let Some(reason) = &self.reason {
            map.serialize_entry("reason", reason)?;
        }
        map.end()
    }
}

/// The reason for a certificate revocation
/// Defined in <https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1>
#[allow(missing_docs)]
#[derive(Debug, Clone)]
#[repr(u8)]
pub enum RevocationReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}

impl Serialize for RevocationReason {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.clone() as u8)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NewAccountPayload<'a> {
    #[serde(flatten)]
    pub(crate) new_account: &'a NewAccount<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) external_account_binding: Option<JoseJson>,
}

/// Input data for [Account](crate::Account) creation
///
/// To be passed into [AccountBuilder::create()](crate::AccountBuilder::create()).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAccount<'a> {
    /// A list of contact URIs (like `mailto:info@example.com`)
    pub contact: &'a [&'a str],
    /// Whether you agree to the terms of service
    pub terms_of_service_agreed: bool,
    /// Set to `true` in order to retrieve an existing account
    ///
    /// Setting this to `false` has not been tested.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub only_return_existing: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Directory {
    pub(crate) new_nonce: String,
    pub(crate) new_account: String,
    pub(crate) new_order: String,
    // The fields below were added later and old `AccountCredentials` may not have it.
    // Newer deserialized account credentials grab a fresh set of `Directory` on
    // deserialization, so they should be fine. Newer fields should be optional, too.
    pub(crate) new_authz: Option<String>,
    pub(crate) revoke_cert: Option<String>,
    pub(crate) key_change: Option<String>,
    // Endpoint for the ACME renewal information (ARI) extension
    //
    // <https://www.rfc-editor.org/rfc/rfc9773.html>
    pub(crate) renewal_info: Option<String>,
    #[serde(default)]
    pub(crate) meta: Meta,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct Meta {
    #[serde(default)]
    pub(crate) profiles: HashMap<String, String>,
}

/// Profile meta information from the server directory
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug)]
pub struct ProfileMeta<'a> {
    pub name: &'a str,
    pub description: &'a str,
}

#[derive(Serialize)]
pub(crate) struct JoseJson {
    pub(crate) protected: String,
    pub(crate) payload: String,
    pub(crate) signature: String,
}

impl JoseJson {
    pub(crate) fn new(
        payload: Option<&impl Serialize>,
        protected: Header<'_>,
        signer: &impl Signer,
    ) -> Result<Self, Error> {
        let protected = base64(&protected)?;
        let payload = match payload {
            Some(data) => base64(&data)?,
            None => String::new(),
        };

        let combined = format!("{protected}.{payload}");
        let signature = signer.sign(combined.as_bytes())?;
        Ok(Self {
            protected,
            payload,
            signature: BASE64_URL_SAFE_NO_PAD.encode(signature),
        })
    }
}

pub(crate) trait Signer {
    type Signature: AsRef<[u8]>;

    fn header<'n, 'u: 'n, 's: 'u>(&'s self, nonce: Option<&'n str>, url: &'u str) -> Header<'n>;

    fn sign(&self, payload: &[u8]) -> Result<Self::Signature, Error>;
}

fn base64(data: &impl Serialize) -> Result<String, serde_json::Error> {
    Ok(BASE64_URL_SAFE_NO_PAD.encode(serde_json::to_vec(data)?))
}

/// An ACME authorization's state as described in RFC 8555 (section 7.1.4)
#[derive(Debug, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "camelCase")]
pub struct AuthorizationState {
    /// The identifier that the account is authorized to represent
    identifier: Identifier,
    /// Current state of the authorization
    pub status: AuthorizationStatus,
    /// Possible challenges for the authorization
    pub challenges: Vec<Challenge>,
    /// Whether the identifier represents a wildcard domain name
    #[serde(default)]
    pub wildcard: bool,
}

impl AuthorizationState {
    /// Creates an [`AuthorizedIdentifier`] for the identifier in this authorization
    pub fn identifier(&self) -> AuthorizedIdentifier<'_> {
        self.identifier.authorized(self.wildcard)
    }
}

/// Status for an [`AuthorizationState`]
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum AuthorizationStatus {
    Pending,
    Valid,
    Invalid,
    Revoked,
    Expired,
    Deactivated,
}

/// Represent an identifier in an ACME [Order](crate::Order)
#[allow(missing_docs)]
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[non_exhaustive]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum Identifier {
    Dns(String),

    /// An IP address (IPv4 or IPv6) identifier
    ///
    /// Note that not all ACME servers will accept an order with an IP address identifier.
    Ip(IpAddr),

    /// Permanent Identifier
    ///
    /// Note that this identifier is only used for attestation.
    PermanentIdentifier(String),

    /// Hardware Module identifier
    ///
    /// Note that this identifier is only used for attestation.
    HardwareModule(String),
}

impl Identifier {
    /// Create an [`AuthorizedIdentifier`], which implements `Display`
    ///
    /// Needs the `wildcard` context bit to determine whether the identifier represents a
    /// wildcard domain.
    pub fn authorized(&self, wildcard: bool) -> AuthorizedIdentifier<'_> {
        AuthorizedIdentifier {
            identifier: self,
            wildcard,
        }
    }
}

/// An [`Identifier`] which knows its `wildcard` context
#[non_exhaustive]
#[derive(Debug)]
pub struct AuthorizedIdentifier<'a> {
    /// The source identifier, missing any wildcard context
    pub identifier: &'a Identifier,
    /// Whether the identifier should be interpreted as a wildcard
    ///
    /// This is only relevant for DNS identifiers and must be false for other
    /// types of identifiers (e.g. IP addresses).
    pub wildcard: bool,
}

impl fmt::Display for AuthorizedIdentifier<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.wildcard, self.identifier) {
            (true, Identifier::Dns(dns)) => f.write_fmt(format_args!("*.{dns}")),
            (false, Identifier::Dns(dns)) => f.write_str(dns),
            (_, Identifier::Ip(addr)) => write!(f, "{addr}"),
            (_, Identifier::PermanentIdentifier(permanent_identifier)) => {
                f.write_str(permanent_identifier)
            }
            (_, Identifier::HardwareModule(hardware_module)) => f.write_str(hardware_module),
        }
    }
}

/// The challenge type
#[allow(missing_docs)]
#[non_exhaustive]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub enum ChallengeType {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
    /// Note: Device attestation support is experimental
    #[serde(rename = "device-attest-01")]
    DeviceAttest01,
    #[serde(untagged)]
    Unknown(String),
}

/// Status of an ACME [Challenge]
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

/// Status of an [Order](crate::Order)
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

/// Helper type to reference Let's Encrypt server URLs
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug)]
pub enum LetsEncrypt {
    Production,
    Staging,
}

impl LetsEncrypt {
    /// Get the directory URL for the given Let's Encrypt server
    pub const fn url(&self) -> &'static str {
        match self {
            Self::Production => "https://acme-v02.api.letsencrypt.org/directory",
            Self::Staging => "https://acme-staging-v02.api.letsencrypt.org/directory",
        }
    }
}

/// ZeroSSL ACME only supports production at the moment
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug)]
pub enum ZeroSsl {
    Production,
}

impl ZeroSsl {
    /// Get the directory URL for the given ZeroSSL server
    pub const fn url(&self) -> &'static str {
        match self {
            Self::Production => "https://acme.zerossl.com/v2/DV90",
        }
    }
}

/// A unique certificate identifier for the ACME renewal information (ARI) extension
///
/// See <https://www.rfc-editor.org/rfc/rfc9773.html#section-4.1> for
/// more information.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateIdentifier<'a> {
    /// The BASE64URL-encoded authority key identifier (AKI) extension `keyIdentifier` of the certificate
    pub authority_key_identifier: Cow<'a, str>,

    /// The BASE64URL-encoded serial number of the certificate
    pub serial: Cow<'a, str>,
}

impl CertificateIdentifier<'_> {
    /// Encode a unique certificate identifier using the provided authority key ID and serial
    ///
    /// `authority_key_identifier` must be the DER-encoded ASN.1 octet string from the
    /// `keyIdentifier` field of the `AuthorityKeyIdentifier` extension found in the certificate
    /// to be identified.
    ///
    /// `serial` must be the DER-encoded ASN.1 serial number from the certificate to be identified.
    /// Care must be taken to use the **encoded** serial number, not a big integer representation.
    ///
    /// The combination uniquely identifies a certificate within all certificates issued by the
    /// same CA.
    ///
    /// See [RFC 5280 §4.1.2.2], [RFC 5280 §4.2.1.1], and [RFC 9773 §4.1]
    ///
    /// [RFC 5280 §4.1.2.2]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2
    /// [RFC 5280 §4.2.1.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.1
    /// [RFC 9773 §4.1]: https://www.rfc-editor.org/rfc/rfc9773.html#section-4.1
    pub fn new(authority_key_identifier: Der<'_>, serial: Der<'_>) -> Self {
        Self {
            authority_key_identifier: BASE64_URL_SAFE_NO_PAD
                .encode(authority_key_identifier)
                .into(),
            serial: BASE64_URL_SAFE_NO_PAD.encode(serial).into(),
        }
    }

    /// Convert the `CertificateIdentifier` into an owned version with a static lifetime
    pub fn into_owned(self) -> CertificateIdentifier<'static> {
        CertificateIdentifier {
            authority_key_identifier: Cow::Owned(self.authority_key_identifier.into_owned()),
            serial: Cow::Owned(self.serial.into_owned()),
        }
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for CertificateIdentifier<'a> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <&str>::deserialize(deserializer)?;

        let Some((aki, serial)) = s.split_once('.') else {
            return Err(de::Error::invalid_value(
                de::Unexpected::Str(s),
                &"a string containing 2 '.'-delimited parts",
            ));
        };

        if serial.contains('.') {
            return Err(de::Error::invalid_value(
                de::Unexpected::Str(s),
                &"only one '.' delimiter should be present",
            ));
        }

        Ok(CertificateIdentifier {
            authority_key_identifier: Cow::Borrowed(aki),
            serial: Cow::Borrowed(serial),
        })
    }
}

impl Serialize for CertificateIdentifier<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "x509-parser")]
impl<'a> TryFrom<&'a CertificateDer<'_>> for CertificateIdentifier<'_> {
    type Error = String;

    fn try_from(cert: &'a CertificateDer<'_>) -> Result<Self, Self::Error> {
        let (_, parsed_cert) = parse_x509_certificate(cert.as_ref())
            .map_err(|e| format!("failed to parse certificate: {e}"))?;

        let Some(authority_key_identifier) =
            parsed_cert
                .iter_extensions()
                .find_map(|ext| match ext.parsed_extension() {
                    ParsedExtension::AuthorityKeyIdentifier(aki_ext) => aki_ext
                        .key_identifier
                        .as_ref()
                        .map(|aki| Der::from_slice(aki.0)),
                    _ => None,
                })
        else {
            return Err(
                "certificate does not contain an Authority Key Identifier (AKI) extension".into(),
            );
        };

        Ok(Self::new(
            authority_key_identifier,
            Der::from_slice(parsed_cert.tbs_certificate.raw_serial()),
        ))
    }
}

impl fmt::Display for CertificateIdentifier<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.authority_key_identifier)?;
        f.write_char('.')?;
        f.write_str(&self.serial)
    }
}

/// Information about a suggested renewal window for a certificate
///
/// See <https://www.rfc-editor.org/rfc/rfc9773.html#section-4.2>
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "time")]
pub struct RenewalInfo {
    /// The suggested renewal window for a certificate
    pub suggested_window: SuggestedWindow,
    /// A URL to a page explaining why the suggested renewal window has its current value
    #[serde(rename = "explanationURL")]
    pub explanation_url: Option<String>,
}

/// A suggested renewal window for a certificate
///
/// See <https://www.rfc-editor.org/rfc/rfc9773.html#section-4.2>
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg(feature = "time")]
pub struct SuggestedWindow {
    /// The start [`OffsetDateTime`] of the suggested renewal window
    #[serde(with = "time::serde::rfc3339")]
    pub start: OffsetDateTime,
    /// The end [`OffsetDateTime`] of the suggested renewal window
    #[serde(with = "time::serde::rfc3339")]
    pub end: OffsetDateTime,
}

fn deserialize_static_certificate_identifier<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<CertificateIdentifier<'static>>, D::Error> {
    let Some(cert_id) = Option::<CertificateIdentifier<'_>>::deserialize(deserializer)? else {
        return Ok(None);
    };

    Ok(Some(cert_id.into_owned()))
}

/// Algorithm identifier for JWS headers
///
/// See the [IANA JOSE registry](https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms)
/// for the full list of registered algorithms.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum SigningAlgorithm {
    /// EdDSA using the Ed25519 parameter set in Section 5.1 of [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)
    ///
    /// [RFC 9864, Section 2.2](https://www.rfc-editor.org/rfc/rfc9864#section-2.2)
    Ed25519,
    /// ECDSA using P-256 and SHA-256
    ///
    /// [RFC 7518, Section 3.4](https://www.rfc-editor.org/rfc/rfc7518#section-3.4)
    Es256,
    /// ECDSA using P-384 and SHA-384
    ///
    /// [RFC 7518, Section 3.4](https://www.rfc-editor.org/rfc/rfc7518#section-3.4)
    Es384,
    /// HMAC using SHA-256
    ///
    /// [RFC 7518, Section 3.2](https://www.rfc-editor.org/rfc/rfc7518#section-3.2)
    Hs256,
    /// RSASSA-PKCS1-v1_5 using SHA-256
    ///
    /// [RFC 7518, Section 3.3](https://www.rfc-editor.org/rfc/rfc7518#section-3.3)
    Rs256,
    /// Other algorithm not represented in the enum
    #[serde(untagged)]
    Other(&'static str),
}

/// Attestation payload used for device-attest-01
///
/// See <https://datatracker.ietf.org/doc/draft-acme-device-attest/> for details.
pub struct DeviceAttestation<'a> {
    /// CBOR encoded attestation payload
    pub att_obj: Cow<'a, [u8]>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Empty {}

#[cfg(test)]
mod tests {
    #[cfg(all(
        feature = "rcgen",
        feature = "x509-parser",
        any(feature = "aws-lc-rs", feature = "ring")
    ))]
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, IsCa, Issuer, KeyIdMethod, KeyPair,
        SerialNumber,
    };

    use super::*;

    const CSR_PEM: &[u8] = include_bytes!("../tests/testdata/csr.pem");
    const CSR_DER: &[u8] = include_bytes!("../tests/testdata/csr.der");

    #[test]
    fn csr_from_pem() {
        assert_eq!(Csr::from_pem(CSR_PEM).unwrap().der(), CSR_DER);
    }

    #[test]
    fn csr_from_der() {
        assert_eq!(Csr::from_der(CSR_DER).der(), CSR_DER);
        assert_eq!(Csr::from(CSR_DER).der(), CSR_DER);
        assert_eq!(Csr::from(CSR_DER.to_vec()).der(), CSR_DER);

        let der = CertificateSigningRequestDer::from(CSR_DER);
        assert_eq!(Csr::from(&der).der(), CSR_DER);
        assert_eq!(Csr::from_der(der).der(), CSR_DER);
    }

    #[test]
    fn csr_from_invalid_pem() {
        // Not PEM at all
        assert!(matches!(Csr::from_pem(CSR_DER), Err(Error::Pem(_))));
        // A PEM section, but not a CSR
        let cert = include_bytes!("../tests/testdata/server.pem");
        assert!(matches!(Csr::from_pem(cert), Err(Error::Pem(_))));
        // Truncated: no end marker
        let truncated = &CSR_PEM[..CSR_PEM.len() / 2];
        assert!(matches!(Csr::from_pem(truncated), Err(Error::Pem(_))));
    }

    #[cfg(feature = "x509-parser")]
    mod validate {
        use super::*;

        const WILDCARD: &[u8] = include_bytes!("../tests/testdata/csr-wildcard.der");
        const CN_OK: &[u8] = include_bytes!("../tests/testdata/csr-cn-ok.der");
        const CN_MISMATCH: &[u8] = include_bytes!("../tests/testdata/csr-cn-mismatch.der");
        const IP: &[u8] = include_bytes!("../tests/testdata/csr-ip.der");
        const NO_SAN: &[u8] = include_bytes!("../tests/testdata/csr-no-san.der");
        const BAD_SIG: &[u8] = include_bytes!("../tests/testdata/csr-bad-sig.der");
        const EMPTY: &[u8] = include_bytes!("../tests/testdata/csr-empty.der");

        fn dns(names: &[&str]) -> Vec<Identifier> {
            names
                .iter()
                .map(|name| Identifier::Dns((*name).to_owned()))
                .collect()
        }

        fn check(der: &[u8], identifiers: &[Identifier], wildcard: bool) -> Result<(), CsrError> {
            let authorized = identifiers
                .iter()
                .map(|identifier| identifier.authorized(wildcard))
                .collect::<Vec<_>>();
            Csr::from_der(der).validate(&authorized)
        }

        #[test]
        fn exact_match() {
            let identifiers = dns(&["example.com", "www.example.com"]);
            check(CSR_DER, &identifiers, false).unwrap();
        }

        #[test]
        fn case_insensitive() {
            let identifiers = dns(&["EXAMPLE.com", "WWW.example.COM"]);
            check(CSR_DER, &identifiers, false).unwrap();
        }

        #[test]
        fn missing_identifier() {
            let identifiers = dns(&["example.com", "www.example.com", "other.example.com"]);
            assert!(matches!(
                check(CSR_DER, &identifiers, false),
                Err(CsrError::MissingIdentifier(name)) if name == "other.example.com"
            ));
        }

        #[test]
        fn unexpected_identifier() {
            let identifiers = dns(&["example.com"]);
            assert!(matches!(
                check(CSR_DER, &identifiers, false),
                Err(CsrError::UnexpectedIdentifier(name)) if name == "www.example.com"
            ));

            // ...unless the policy allows it
            let authorized = identifiers
                .iter()
                .map(|identifier| identifier.authorized(false))
                .collect::<Vec<_>>();
            let policy = CsrPolicy::new().allow_extra_identifiers(true);
            Csr::from_der(CSR_DER)
                .validate_with(&authorized, &policy)
                .unwrap();
        }

        #[test]
        fn wildcard() {
            // The authorization identifier for `*.example.com` is `example.com` plus the
            // wildcard bit, so this only matches if the bit is taken into account.
            let identifiers = dns(&["example.com"]);
            check(WILDCARD, &identifiers, true).unwrap();
            assert!(matches!(
                check(WILDCARD, &identifiers, false),
                Err(CsrError::MissingIdentifier(name)) if name == "example.com"
            ));
        }

        #[test]
        fn ip_identifiers() {
            // Written as `2001:db8::1` in the CSR, spelled out here: comparing as text would
            // not match.
            let identifiers = vec![
                Identifier::Ip("127.0.0.1".parse().unwrap()),
                Identifier::Ip("2001:0db8:0000:0000:0000:0000:0000:0001".parse().unwrap()),
            ];
            check(IP, &identifiers, false).unwrap();

            let identifiers = vec![Identifier::Ip("127.0.0.2".parse().unwrap())];
            assert!(matches!(
                check(IP, &identifiers, false),
                Err(CsrError::MissingIdentifier(_))
            ));
        }

        #[test]
        fn common_name() {
            let identifiers = dns(&["example.com", "www.example.com"]);
            check(CN_OK, &identifiers, false).unwrap();

            let identifiers = dns(&["example.com"]);
            assert!(matches!(
                check(CN_MISMATCH, &identifiers, false),
                Err(CsrError::CommonNameNotInSan(name)) if name == "other.example.com"
            ));
        }

        #[test]
        fn no_subject_alt_name() {
            let identifiers = dns(&["example.com"]);
            assert!(matches!(
                check(NO_SAN, &identifiers, false),
                Err(CsrError::NoSubjectAltName)
            ));

            // That CSR puts the name in the subject instead, which is the other half of why
            // a CA rejects it.
            assert!(matches!(
                check(NO_SAN, &[], false),
                Err(CsrError::CommonNameNotInSan(name)) if name == "example.com"
            ));

            // With no identifiers to cover, a CSR without the extension is not a problem.
            check(EMPTY, &[], false).unwrap();
        }

        #[test]
        fn not_a_csr() {
            assert!(matches!(
                check(CSR_PEM, &[], false),
                Err(CsrError::Parse(_))
            ));

            let mut trailing = CSR_DER.to_vec();
            trailing.push(0);
            assert!(matches!(
                check(&trailing, &[], false),
                Err(CsrError::Parse(
                    "trailing data after the certification request"
                ))
            ));
        }

        #[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
        #[test]
        fn bad_signature() {
            let identifiers = dns(&["example.com", "www.example.com"]);
            assert!(matches!(
                check(BAD_SIG, &identifiers, false),
                Err(CsrError::BadSignature)
            ));
        }

        #[cfg(all(feature = "rcgen", any(feature = "aws-lc-rs", feature = "ring")))]
        #[test]
        fn account_key_reuse() {
            use rustls_pki_types::PrivatePkcs8KeyDer;

            #[cfg(feature = "aws-lc-rs")]
            let provider = crate::CryptoProvider::aws_lc_rs();
            #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
            let provider = crate::CryptoProvider::ring();

            // A CSR signed with the same key pair the account uses is not acceptable.
            let key_pair = KeyPair::generate().unwrap();
            let account_key = crate::Key::from_pkcs8_der(
                PrivatePkcs8KeyDer::from(key_pair.serialized_der().to_vec()),
                provider,
            )
            .unwrap();

            let mut params = CertificateParams::new(vec!["example.com".to_owned()]).unwrap();
            params.distinguished_name = DistinguishedName::new();
            let csr = params.serialize_request(&key_pair).unwrap();
            assert!(matches!(
                Csr::from(csr.der()).check_account_key(&account_key),
                Err(CsrError::AccountKeyReuse)
            ));

            // A CSR for any other key pair is fine.
            let other = KeyPair::generate().unwrap();
            let csr = params.serialize_request(&other).unwrap();
            Csr::from(csr.der())
                .check_account_key(&account_key)
                .unwrap();
        }
    }

    #[cfg(feature = "fs")]
    #[test]
    fn csr_from_pem_file() {
        let csr = Csr::from_pem_file("tests/testdata/csr.pem").unwrap();
        assert_eq!(csr.der(), CSR_DER);
    }

    // https://datatracker.ietf.org/doc/html/rfc8555#section-7.4
    #[test]
    fn order() {
        const ORDER: &str = r#"{
          "status": "pending",
          "expires": "2016-01-05T14:09:07.99Z",

          "notBefore": "2016-01-01T00:00:00Z",
          "notAfter": "2016-01-08T00:00:00Z",

          "identifiers": [
            { "type": "dns", "value": "www.example.org" },
            { "type": "dns", "value": "example.org" }
          ],

          "authorizations": [
            "https://example.com/acme/authz/PAniVnsZcis",
            "https://example.com/acme/authz/r4HqLzrSrpI"
          ],

          "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
        }"#;

        let obj = serde_json::from_str::<OrderState>(ORDER).unwrap();
        assert_eq!(obj.status, OrderStatus::Pending);
        assert_eq!(obj.authorizations.len(), 2);
        assert_eq!(
            obj.finalize,
            "https://example.com/acme/order/TOlocE8rfgo/finalize"
        );
    }

    // https://datatracker.ietf.org/doc/html/rfc8555#section-7.5.1
    #[test]
    fn authorization() {
        const AUTHORIZATION: &str = r#"{
          "status": "valid",
          "expires": "2018-09-09T14:09:01.13Z",

          "identifier": {
            "type": "dns",
            "value": "www.example.org"
          },

          "challenges": [
            {
              "type": "http-01",
              "url": "https://example.com/acme/chall/prV_B7yEyA4",
              "status": "valid",
              "validated": "2014-12-01T12:05:13.72Z",
              "token": "IlirfxKKXAsHtmzK29Pj8A"
            }
          ]
        }"#;

        let obj = serde_json::from_str::<AuthorizationState>(AUTHORIZATION).unwrap();
        assert_eq!(obj.status, AuthorizationStatus::Valid);
        assert_eq!(obj.identifier, Identifier::Dns("www.example.org".into()));
        assert_eq!(obj.challenges.len(), 1);
    }

    // https://datatracker.ietf.org/doc/html/rfc8555#section-8.4
    #[test]
    fn challenge() {
        const CHALLENGE: &str = r#"{
          "type": "dns-01",
          "url": "https://example.com/acme/chall/Rg5dV14Gh1Q",
          "status": "pending",
          "token": "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"
        }"#;

        let obj = serde_json::from_str::<Challenge>(CHALLENGE).unwrap();
        assert_eq!(obj.r#type, ChallengeType::Dns01);
        assert_eq!(obj.url, "https://example.com/acme/chall/Rg5dV14Gh1Q");
        assert_eq!(obj.status, ChallengeStatus::Pending);
        assert_eq!(obj.token, "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA");
    }

    // https://datatracker.ietf.org/doc/html/rfc8555#section-7.6
    #[test]
    fn problem() {
        const PROBLEM: &str = r#"{
          "type": "urn:ietf:params:acme:error:unauthorized",
          "detail": "No authorization provided for name example.org"
        }"#;

        let obj = serde_json::from_str::<Problem>(PROBLEM).unwrap();
        assert_eq!(
            obj.r#type,
            Some("urn:ietf:params:acme:error:unauthorized".into())
        );
        assert_eq!(
            obj.detail,
            Some("No authorization provided for name example.org".into())
        );
        assert!(obj.subproblems.is_empty());
    }

    // https://www.rfc-editor.org/rfc/rfc8555#section-6.7.1
    #[test]
    fn subproblems() {
        const PROBLEM: &str = r#"{
            "type": "urn:ietf:params:acme:error:malformed",
            "detail": "Some of the identifiers requested were rejected",
            "subproblems": [
                {
                    "type": "urn:ietf:params:acme:error:malformed",
                    "detail": "Invalid underscore in DNS name \"_example.org\"",
                    "identifier": {
                        "type": "dns",
                        "value": "_example.org"
                    }
                },
                {
                    "type": "urn:ietf:params:acme:error:rejectedIdentifier",
                    "detail": "This CA will not issue for \"example.net\"",
                    "identifier": {
                        "type": "dns",
                        "value": "example.net"
                    }
                }
            ]
        }"#;

        let obj = serde_json::from_str::<Problem>(PROBLEM).unwrap();
        assert_eq!(
            obj.r#type,
            Some("urn:ietf:params:acme:error:malformed".into())
        );
        assert_eq!(
            obj.detail,
            Some("Some of the identifiers requested were rejected".into())
        );

        let subproblems = &obj.subproblems;
        assert_eq!(subproblems.len(), 2);

        let first_subproblem = subproblems.first().unwrap();
        assert_eq!(
            first_subproblem.identifier,
            Some(Identifier::Dns("_example.org".into()))
        );
        assert_eq!(
            first_subproblem.r#type,
            Some("urn:ietf:params:acme:error:malformed".into())
        );
        assert_eq!(
            first_subproblem.detail,
            Some(r#"Invalid underscore in DNS name "_example.org""#.into())
        );

        let second_subproblem = subproblems.get(1).unwrap();
        assert_eq!(
            second_subproblem.identifier,
            Some(Identifier::Dns("example.net".into()))
        );
        assert_eq!(
            second_subproblem.r#type,
            Some("urn:ietf:params:acme:error:rejectedIdentifier".into())
        );
        assert_eq!(
            second_subproblem.detail,
            Some(r#"This CA will not issue for "example.net""#.into())
        );

        let expected_display = "\
    API error: Some of the identifiers requested were rejected (urn:ietf:params:acme:error:malformed): \
    2 subproblems: \
    for \"_example.org\": Invalid underscore in DNS name \"_example.org\" (urn:ietf:params:acme:error:malformed), \
    for \"example.net\": This CA will not issue for \"example.net\" (urn:ietf:params:acme:error:rejectedIdentifier)";
        assert_eq!(format!("{obj}"), expected_display);
    }

    // https://www.rfc-editor.org/rfc/rfc9773.html#section-4.1
    #[test]
    fn certificate_identifier() {
        const ORDER: &str = r#"{
          "status": "pending",
          "expires": "2016-01-05T14:09:07.99Z",

          "notBefore": "2016-01-01T00:00:00Z",
          "notAfter": "2016-01-08T00:00:00Z",

          "identifiers": [
            { "type": "dns", "value": "www.example.org" },
            { "type": "dns", "value": "example.org" }
          ],

          "authorizations": [
            "https://example.com/acme/authz/PAniVnsZcis",
            "https://example.com/acme/authz/r4HqLzrSrpI"
          ],

          "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize",

          "replaces": "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"
        }"#;

        let order = serde_json::from_str::<OrderState>(ORDER).unwrap();
        let cert_id = order.replaces.unwrap();
        assert_eq!(
            cert_id.authority_key_identifier,
            "aYhba4dGQEHhs3uEe6CuLN4ByNQ"
        );
        assert_eq!(cert_id.serial, "AIdlQyE");

        let serialized = serde_json::to_string(&cert_id).unwrap();
        assert_eq!(serialized, r#""aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE""#);
    }

    #[cfg(all(
        feature = "rcgen",
        feature = "x509-parser",
        any(feature = "aws-lc-rs", feature = "ring")
    ))]
    #[test]
    fn encoded_certificate_identifier_from_cert() {
        // Generate a CA key_pair and self-signed cert with a specific subject key identifier.
        let ca_key_id = vec![0xC0, 0xFF, 0xEE];
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_identifier_method = KeyIdMethod::PreSpecified(ca_key_id);
        let ca = Issuer::new(ca_params, ca_key);

        // Generate an end entity certificate issued by the CA, with a specific serial number
        // and an AKI extension.
        let ee_key = KeyPair::generate().unwrap();
        let ee_serial = [0xCA, 0xFE];
        let mut ee_params = CertificateParams::new(["example.com".to_owned()]).unwrap();
        ee_params.distinguished_name = DistinguishedName::new();
        ee_params.serial_number = Some(SerialNumber::from_slice(ee_serial.as_slice()));
        ee_params.use_authority_key_identifier_extension = true;
        let ee_cert = ee_params.signed_by(&ee_key, &ca).unwrap();

        // Extract the AKI and serial number from the EE certificate and create an encoded
        // certificate identifier.
        let encoded = CertificateIdentifier::try_from(ee_cert.der()).unwrap();

        // We should arrive at the expected encoded certificate identifier.
        assert_eq!(format!("{encoded}"), "wP_u.AMr-");
    }

    // https://www.rfc-editor.org/rfc/rfc9773.html#section-4.2
    #[test]
    #[cfg(feature = "time")]
    fn renewal_info() {
        const INFO: &str = r#"{
          "suggestedWindow": {
            "start": "2025-01-02T04:00:00Z",
            "end": "2025-01-03T04:00:00Z"
          },
          "explanationURL": "https://acme.example.com/docs/ari"
        }
        "#;

        let info = serde_json::from_str::<RenewalInfo>(INFO).unwrap();
        assert_eq!(
            info.explanation_url.unwrap(),
            "https://acme.example.com/docs/ari"
        );
        let window = info.suggested_window;
        assert_eq!(window.start.day(), 2);
        assert_eq!(window.end.day(), 3);
    }
}
