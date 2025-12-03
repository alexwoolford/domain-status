//! Security warning types.

/// Types of security warnings that can be detected
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SecurityWarning {
    /// Site uses HTTP instead of HTTPS
    NoHttps,
    /// TLS version is too old (< TLS 1.2)
    WeakTls,
    /// Missing Strict-Transport-Security (HSTS) header
    MissingHsts,
    /// Missing Content-Security-Policy header
    MissingCsp,
    /// Missing X-Content-Type-Options header
    MissingContentTypeOptions,
    /// Missing X-Frame-Options header
    MissingFrameOptions,
}

impl SecurityWarning {
    /// Returns a human-readable description of the warning
    pub fn description(&self) -> &'static str {
        match self {
            SecurityWarning::NoHttps => "Site uses HTTP instead of HTTPS",
            SecurityWarning::WeakTls => "TLS version is too old (< TLS 1.2)",
            SecurityWarning::MissingHsts => "Missing Strict-Transport-Security (HSTS) header",
            SecurityWarning::MissingCsp => "Missing Content-Security-Policy header",
            SecurityWarning::MissingContentTypeOptions => "Missing X-Content-Type-Options header",
            SecurityWarning::MissingFrameOptions => "Missing X-Frame-Options header",
        }
    }

    /// Returns a short code for the warning (for database storage)
    pub fn code(&self) -> &'static str {
        match self {
            SecurityWarning::NoHttps => "no_https",
            SecurityWarning::WeakTls => "weak_tls",
            SecurityWarning::MissingHsts => "missing_hsts",
            SecurityWarning::MissingCsp => "missing_csp",
            SecurityWarning::MissingContentTypeOptions => "missing_content_type_options",
            SecurityWarning::MissingFrameOptions => "missing_frame_options",
        }
    }
}
