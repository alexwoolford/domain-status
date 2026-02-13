//! Application-level data models.
//!
//! This module defines data structures used throughout the application:
//! - `TlsCertificateInfo` - TLS certificate details extracted from connections
//! - `KeyAlgorithm` - TLS public key algorithm enum
//!
//! These models are separate from database models (in `storage::models`) to
//! maintain a clear separation between application logic and persistence.

use chrono::NaiveDateTime;
use std::fmt;

/// Public key algorithm used in a TLS certificate.
///
/// Eliminates primitive obsession by replacing raw `String` algorithm names
/// with a type-safe enum. The `Other(String)` variant handles unknown OIDs
/// that don't map to a recognized algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// RSA (OID 1.2.840.113549.1.1.1)
    RSA,
    /// ECDSA (OID 1.2.840.10045.2.1)
    ECDSA,
    /// Ed25519 (OID 1.3.101.112)
    Ed25519,
    /// Ed448 (OID 1.3.101.113)
    Ed448,
    /// Fallback for unknown OIDs (stores the raw OID string).
    Other(String),
}

impl KeyAlgorithm {
    /// Returns the algorithm name as a string slice.
    ///
    /// For known algorithms, returns a static string.
    /// For `Other`, returns the stored OID string.
    pub fn as_str(&self) -> &str {
        match self {
            KeyAlgorithm::RSA => "RSA",
            KeyAlgorithm::ECDSA => "ECDSA",
            KeyAlgorithm::Ed25519 => "Ed25519",
            KeyAlgorithm::Ed448 => "Ed448",
            KeyAlgorithm::Other(oid) => oid,
        }
    }

    /// Parses a key algorithm from an X.509 OID string.
    pub fn from_oid(oid_str: &str) -> Self {
        if oid_str.contains("1.2.840.113549.1.1.1") {
            KeyAlgorithm::RSA
        } else if oid_str.contains("1.2.840.10045.2.1") {
            KeyAlgorithm::ECDSA
        } else if oid_str.contains("1.3.101.112") {
            KeyAlgorithm::Ed25519
        } else if oid_str.contains("1.3.101.113") {
            KeyAlgorithm::Ed448
        } else {
            KeyAlgorithm::Other(oid_str.to_string())
        }
    }
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// TLS protocol version negotiated during an HTTPS connection.
///
/// Eliminates primitive obsession by replacing raw `String` version names
/// with a type-safe enum. This fixes a subtle bug where the Debug format
/// of rustls versions (`TLS13`) didn't match the string comparisons in
/// security analysis (`"TLSv1.3"`), making the weak-TLS check fragile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    /// TLS 1.0 (insecure)
    Tls10,
    /// TLS 1.1 (insecure)
    Tls11,
    /// TLS 1.2 (secure)
    Tls12,
    /// TLS 1.3 (secure)
    Tls13,
    /// SSL 3.0 (insecure)
    Ssl30,
    /// Unknown or unrecognized protocol version
    Unknown,
}

impl TlsVersion {
    /// Returns the version name as a string slice.
    pub fn as_str(&self) -> &'static str {
        match self {
            TlsVersion::Tls10 => "TLSv1.0",
            TlsVersion::Tls11 => "TLSv1.1",
            TlsVersion::Tls12 => "TLSv1.2",
            TlsVersion::Tls13 => "TLSv1.3",
            TlsVersion::Ssl30 => "SSLv3",
            TlsVersion::Unknown => "Unknown",
        }
    }

    /// Returns `true` if this TLS version is considered weak/insecure.
    ///
    /// TLS 1.2 and TLS 1.3 are considered secure. Everything else
    /// (TLS 1.1, TLS 1.0, SSLv3, Unknown) is considered weak.
    pub fn is_weak(&self) -> bool {
        !matches!(self, TlsVersion::Tls12 | TlsVersion::Tls13)
    }
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// TLS/SSL certificate information extracted from an HTTPS connection.
///
/// Contains all relevant certificate details including version, subject, issuer,
/// validity period, certificate OIDs (from policies, extended key usage, and extensions),
/// cipher suite, and key algorithm.
/// All fields are optional to handle cases where certificate information cannot be extracted.
///
/// # Fields
///
/// * `tls_version` - TLS protocol version (e.g., "TLSv1.3")
/// * `subject` - Certificate subject (e.g., "CN=example.com")
/// * `issuer` - Certificate issuer (e.g., "CN=Let's Encrypt")
/// * `valid_from` - Certificate validity start date
/// * `valid_to` - Certificate validity end date
/// * `oids` - Set of certificate OIDs (includes policy OIDs, extended key usage OIDs, and extension OIDs)
/// * `cipher_suite` - Negotiated cipher suite (e.g., "TLS13_AES_256_GCM_SHA384")
/// * `key_algorithm` - Public key algorithm
/// * `subject_alternative_names` - DNS names from the Subject Alternative Name extension (for linking domains sharing certificates)
pub struct CertificateInfo {
    pub tls_version: Option<TlsVersion>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub valid_from: Option<NaiveDateTime>,
    pub valid_to: Option<NaiveDateTime>,
    pub oids: Option<std::collections::HashSet<String>>,
    pub cipher_suite: Option<String>,
    pub key_algorithm: Option<KeyAlgorithm>,
    pub subject_alternative_names: Option<Vec<String>>,
}
