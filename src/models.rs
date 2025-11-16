use chrono::NaiveDateTime;

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
/// * `oids` - JSON-serialized set of certificate OIDs (includes policy OIDs, extended key usage OIDs, and extension OIDs)
/// * `cipher_suite` - Negotiated cipher suite (e.g., "TLS13_AES_256_GCM_SHA384")
/// * `key_algorithm` - Public key algorithm (e.g., "RSA", "ECDSA", "Ed25519")
pub struct CertificateInfo {
    pub tls_version: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub valid_from: Option<NaiveDateTime>,
    pub valid_to: Option<NaiveDateTime>,
    pub oids: Option<String>,
    pub cipher_suite: Option<String>,
    pub key_algorithm: Option<String>,
}
