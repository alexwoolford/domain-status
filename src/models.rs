use chrono::NaiveDateTime;

/// TLS/SSL certificate information extracted from an HTTPS connection.
///
/// Contains all relevant certificate details including version, subject, issuer,
/// validity period, and certificate policy OIDs. All fields are optional to handle
/// cases where certificate information cannot be extracted.
///
/// # Fields
///
/// * `tls_version` - TLS protocol version (e.g., "TLSv1.3")
/// * `subject` - Certificate subject (e.g., "CN=example.com")
/// * `issuer` - Certificate issuer (e.g., "CN=Let's Encrypt")
/// * `valid_from` - Certificate validity start date
/// * `valid_to` - Certificate validity end date
/// * `oids` - JSON-serialized set of certificate policy OIDs
pub struct CertificateInfo {
    pub tls_version: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub valid_from: Option<NaiveDateTime>,
    pub valid_to: Option<NaiveDateTime>,
    pub oids: Option<String>,
}
