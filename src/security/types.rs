//! Security warning types.

/// Types of security warnings that can be detected
///
/// **Note:** The four `Missing*` variants are no longer produced by
/// [`crate::security::analyze_security`] and are therefore never persisted into
/// `url_security_warnings`. They are retained here only so any code that matches on
/// `SecurityWarning` (e.g. `description()`/`code()` callers) continues to compile.
/// Header absence is a checklist item, not an observed finding, and is derivable
/// on demand from the `url_security_headers` table instead.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SecurityWarning {
    /// Site uses HTTP instead of HTTPS
    NoHttps,
    /// TLS version is too old (< TLS 1.2)
    WeakTls,
    /// Missing Strict-Transport-Security (HSTS) header. No longer emitted; see enum docs.
    #[allow(dead_code)]
    // retained for backward-compat matching; analyze_security no longer constructs it
    MissingHsts,
    /// Missing Content-Security-Policy header. No longer emitted; see enum docs.
    #[allow(dead_code)]
    // retained for backward-compat matching; analyze_security no longer constructs it
    MissingCsp,
    /// Missing X-Content-Type-Options header. No longer emitted; see enum docs.
    #[allow(dead_code)]
    // retained for backward-compat matching; analyze_security no longer constructs it
    MissingContentTypeOptions,
    /// Missing X-Frame-Options header. No longer emitted; see enum docs.
    #[allow(dead_code)]
    // retained for backward-compat matching; analyze_security no longer constructs it
    MissingFrameOptions,
    /// Invalid or untrusted SSL certificate (self-signed, expired, or hostname mismatch)
    InvalidCertificate,
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
            SecurityWarning::InvalidCertificate => {
                "Invalid or untrusted SSL certificate (self-signed, expired, or hostname mismatch)"
            }
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
            SecurityWarning::InvalidCertificate => "invalid_certificate",
        }
    }
}
