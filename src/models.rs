use chrono::NaiveDateTime;

/// TLS certificate information extracted from an HTTPS connection.
pub struct CertificateInfo {
    pub tls_version: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub valid_from: Option<NaiveDateTime>,
    pub valid_to: Option<NaiveDateTime>,
    pub oids: Option<String>,
}
