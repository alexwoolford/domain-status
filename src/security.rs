//! Security analysis and warning detection.
//!
//! This module analyzes HTTP responses and TLS configurations to identify
//! security issues and best practice violations:
//! - Missing HTTPS
//! - Weak TLS versions
//! - Missing security headers (HSTS, CSP, etc.)
//!
//! Warnings are stored in the database for later analysis.

use std::collections::HashMap;

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

/// Analyzes collected data and returns a list of security warnings
///
/// # Arguments
///
/// * `final_url` - The final URL after redirects (to check if HTTPS)
/// * `tls_version` - TLS version used (if HTTPS)
/// * `security_headers` - Map of security headers found
///
/// # Returns
///
/// A vector of security warnings found
pub fn analyze_security(
    final_url: &str,
    tls_version: &Option<String>,
    security_headers: &HashMap<String, String>,
) -> Vec<SecurityWarning> {
    let mut warnings = Vec::new();

    // Check if site uses HTTP (no HTTPS)
    if !final_url.starts_with("https://") {
        warnings.push(SecurityWarning::NoHttps);
        // If no HTTPS, we can't check TLS version, so return early
        return warnings;
    }

    // Check TLS version (only if HTTPS)
    if let Some(version) = tls_version {
        if is_weak_tls(version) {
            warnings.push(SecurityWarning::WeakTls);
        }
    }

    // Check for missing security headers (case-insensitive)
    // Headers are stored with their original case, so we need to check case-insensitively
    let has_hsts = security_headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case("strict-transport-security"));
    if !has_hsts {
        warnings.push(SecurityWarning::MissingHsts);
    }

    let has_csp = security_headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case("content-security-policy"));
    if !has_csp {
        warnings.push(SecurityWarning::MissingCsp);
    }

    let has_content_type_options = security_headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case("x-content-type-options"));
    if !has_content_type_options {
        warnings.push(SecurityWarning::MissingContentTypeOptions);
    }

    let has_frame_options = security_headers
        .keys()
        .any(|k| k.eq_ignore_ascii_case("x-frame-options"));
    if !has_frame_options {
        warnings.push(SecurityWarning::MissingFrameOptions);
    }

    warnings
}

/// Checks if a TLS version is considered weak (< TLS 1.2)
///
/// # Arguments
///
/// * `version` - TLS version string (e.g., "TLSv1.2", "TLSv1.3", "SSLv3")
///
/// # Returns
///
/// `true` if the TLS version is weak, `false` otherwise
fn is_weak_tls(version: &str) -> bool {
    // Normalize to lowercase and normalize separators (replace spaces/underscores with dots)
    let version_normalized = version
        .to_lowercase()
        .replace(' ', "")
        .replace('_', ".")
        .replace("tlsv", "tls");

    // TLS 1.3 and TLS 1.2 are considered secure
    // Check for various formats: "tlsv1.3", "tls1.3", "tls 1.3", "tlsv1_3", etc.
    // After normalization, these become: "tls1.3" or "tls1.2"
    if version_normalized.contains("tls1.3") || version_normalized == "tls1.3" {
        return false;
    }
    if version_normalized.contains("tls1.2") || version_normalized == "tls1.2" {
        return false;
    }

    // Everything else (TLS 1.1, TLS 1.0, SSLv3, SSLv2) is considered weak
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_weak_tls() {
        assert!(!is_weak_tls("TLSv1.3"));
        assert!(!is_weak_tls("TLSv1.2"));
        assert!(!is_weak_tls("TLSv1_3")); // Format used by rustls
        assert!(!is_weak_tls("TLSv1_2")); // Format used by rustls
        assert!(!is_weak_tls("TLS 1.3"));
        assert!(!is_weak_tls("TLS 1.2"));
        assert!(is_weak_tls("TLSv1.1"));
        assert!(is_weak_tls("TLSv1.0"));
        assert!(is_weak_tls("SSLv3"));
        assert!(is_weak_tls("SSLv2"));
    }

    #[test]
    fn test_analyze_security_no_https() {
        let headers = HashMap::new();
        let warnings = analyze_security("http://example.com", &None, &headers);
        assert_eq!(warnings.len(), 1);
        assert!(warnings.contains(&SecurityWarning::NoHttps));
    }

    #[test]
    fn test_analyze_security_weak_tls() {
        let mut headers = HashMap::new();
        headers.insert(
            "strict-transport-security".to_string(),
            "max-age=31536000".to_string(),
        );
        let warnings = analyze_security(
            "https://example.com",
            &Some("TLSv1.1".to_string()),
            &headers,
        );
        assert!(warnings.contains(&SecurityWarning::WeakTls));
    }

    #[test]
    fn test_analyze_security_missing_headers() {
        let headers = HashMap::new();
        let warnings = analyze_security(
            "https://example.com",
            &Some("TLSv1.3".to_string()),
            &headers,
        );
        assert!(warnings.contains(&SecurityWarning::MissingHsts));
        assert!(warnings.contains(&SecurityWarning::MissingCsp));
        assert!(warnings.contains(&SecurityWarning::MissingContentTypeOptions));
        assert!(warnings.contains(&SecurityWarning::MissingFrameOptions));
    }

    #[test]
    fn test_analyze_security_all_good() {
        let mut headers = HashMap::new();
        headers.insert(
            "strict-transport-security".to_string(),
            "max-age=31536000".to_string(),
        );
        headers.insert(
            "content-security-policy".to_string(),
            "default-src 'self'".to_string(),
        );
        headers.insert("x-content-type-options".to_string(), "nosniff".to_string());
        headers.insert("x-frame-options".to_string(), "DENY".to_string());
        let warnings = analyze_security(
            "https://example.com",
            &Some("TLSv1.3".to_string()),
            &headers,
        );
        assert_eq!(warnings.len(), 0);
    }
}
