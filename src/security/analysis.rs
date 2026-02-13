//! Security analysis functions.

use std::collections::HashMap;

use super::SecurityWarning;
use crate::models::TlsVersion;

/// Analyzes collected data and returns a list of security warnings
///
/// # Arguments
///
/// * `final_url` - The final URL after redirects (to check if HTTPS)
/// * `tls_version` - TLS version used (if HTTPS)
/// * `security_headers` - Map of security headers found
/// * `cert_subject` - Certificate subject (if HTTPS)
/// * `cert_issuer` - Certificate issuer (if HTTPS)
/// * `cert_valid_to` - Certificate expiration date (if HTTPS)
/// * `cert_sans` - Certificate Subject Alternative Names (if HTTPS)
///
/// # Returns
///
/// A vector of security warnings found
pub fn analyze_security(
    final_url: &str,
    tls_version: &Option<TlsVersion>,
    security_headers: &HashMap<String, String>,
    cert_subject: &Option<String>,
    cert_issuer: &Option<String>,
    cert_valid_to: &Option<chrono::NaiveDateTime>,
    _cert_sans: &Option<Vec<String>>,
) -> Vec<SecurityWarning> {
    let mut warnings = Vec::new();

    // Check if site uses HTTP (no HTTPS)
    if !final_url.starts_with("https://") {
        warnings.push(SecurityWarning::NoHttps);
        // If no HTTPS, we can't check TLS version, so return early
        return warnings;
    }

    // Check TLS version (only if HTTPS) - type-safe comparison via TlsVersion::is_weak()
    if let Some(version) = tls_version {
        if version.is_weak() {
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

    // Check certificate validity
    // Since we always allow invalid certificates to maximize data capture,
    // we need to validate the certificate ourselves and record issues
    if let (Some(subject), Some(issuer), Some(valid_to)) =
        (cert_subject, cert_issuer, cert_valid_to)
    {
        let now = chrono::Utc::now().naive_utc();

        // Check if certificate is expired
        let is_expired = *valid_to < now;

        // Check if certificate is self-signed (subject == issuer)
        // X.509 DNs from x509-parser are normalized, so direct string comparison should work
        // However, we normalize by trimming whitespace and comparing case-insensitively
        // to handle any edge cases
        let is_self_signed = subject.trim().eq_ignore_ascii_case(issuer.trim());

        if is_expired || is_self_signed {
            warnings.push(SecurityWarning::InvalidCertificate);
        }
        // Note: Hostname mismatch detection is complex and would require
        // parsing the certificate subject and SANs, which is handled by
        // the TLS library. Since we're accepting all certs, we can't easily
        // detect hostname mismatches without re-implementing the validation logic.
        // For now, we detect expired and self-signed certificates.
    } else if final_url.starts_with("https://") {
        // If we have HTTPS but no certificate info, it indicates
        // a certificate extraction failure. This could mean:
        // - The certificate was so broken we couldn't parse it
        // - TLS handshake failed completely
        // - Network/connection issues
        // This is a security concern (can't verify the certificate) and should be recorded
        warnings.push(SecurityWarning::InvalidCertificate);
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;

    #[test]
    fn test_tls_version_secure_versions() {
        // TLS 1.2 and above are secure
        assert!(!TlsVersion::Tls12.is_weak());
        assert!(!TlsVersion::Tls13.is_weak());
    }

    #[test]
    fn test_tls_version_insecure_versions() {
        // TLS 1.1 and below are weak
        assert!(TlsVersion::Tls11.is_weak());
        assert!(TlsVersion::Tls10.is_weak());
        assert!(TlsVersion::Ssl30.is_weak());
    }

    #[test]
    fn test_tls_version_unknown_defaults_to_weak() {
        // Unknown versions should default to weak for safety
        assert!(TlsVersion::Unknown.is_weak());
    }

    #[test]
    fn test_tls_version_display() {
        assert_eq!(TlsVersion::Tls13.as_str(), "TLSv1.3");
        assert_eq!(TlsVersion::Tls12.as_str(), "TLSv1.2");
        assert_eq!(TlsVersion::Tls11.as_str(), "TLSv1.1");
        assert_eq!(TlsVersion::Tls10.as_str(), "TLSv1.0");
        assert_eq!(TlsVersion::Ssl30.as_str(), "SSLv3");
        assert_eq!(TlsVersion::Unknown.as_str(), "Unknown");
    }

    #[test]
    fn test_analyze_security_https_no_warnings() {
        let security_headers = HashMap::new();

        let warnings = analyze_security(
            "https://example.com",
            &None, // no TLS version provided
            &security_headers,
            &None, // no certificate
            &None,
            &None,
            &None,
        );

        // Should have warnings for missing security headers, but not for HTTPS
        assert!(!warnings.contains(&SecurityWarning::NoHttps));
    }

    #[test]
    fn test_analyze_security_http_generates_warning() {
        let security_headers = HashMap::new();

        let warnings = analyze_security(
            "http://example.com", // HTTP not HTTPS
            &None,
            &security_headers,
            &None,
            &None,
            &None,
            &None,
        );

        assert!(warnings.contains(&SecurityWarning::NoHttps));
    }

    #[test]
    fn test_analyze_security_missing_security_headers() {
        let security_headers = HashMap::new(); // Empty headers

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &security_headers,
            &None,
            &None,
            &None,
            &None,
        );

        // Should warn about missing security headers
        assert!(warnings.contains(&SecurityWarning::MissingHsts));
        assert!(warnings.contains(&SecurityWarning::MissingCsp));
        assert!(warnings.contains(&SecurityWarning::MissingContentTypeOptions));
        assert!(warnings.contains(&SecurityWarning::MissingFrameOptions));
    }

    #[test]
    fn test_analyze_security_with_all_headers() {
        let mut security_headers = HashMap::new();
        security_headers.insert(
            "strict-transport-security".to_string(),
            "max-age=31536000".to_string(),
        );
        security_headers.insert(
            "content-security-policy".to_string(),
            "default-src 'self'".to_string(),
        );
        security_headers.insert("x-content-type-options".to_string(), "nosniff".to_string());
        security_headers.insert("x-frame-options".to_string(), "DENY".to_string());

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &security_headers,
            &None,
            &None,
            &None,
            &None,
        );

        // Should not warn about missing headers
        assert!(!warnings.contains(&SecurityWarning::MissingHsts));
        assert!(!warnings.contains(&SecurityWarning::MissingCsp));
        assert!(!warnings.contains(&SecurityWarning::MissingContentTypeOptions));
        assert!(!warnings.contains(&SecurityWarning::MissingFrameOptions));
    }

    #[test]
    fn test_analyze_security_weak_tls() {
        let security_headers = HashMap::new();

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls10), // Weak TLS version
            &security_headers,
            &None,
            &None,
            &None,
            &None,
        );

        assert!(warnings.contains(&SecurityWarning::WeakTls));
    }

    #[test]
    fn test_analyze_security_strong_tls() {
        let security_headers = HashMap::new();

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13), // Strong TLS version
            &security_headers,
            &None,
            &None,
            &None,
            &None,
        );

        assert!(!warnings.contains(&SecurityWarning::WeakTls));
    }

    #[test]
    fn test_analyze_security_expired_certificate() {
        let security_headers = HashMap::new();

        // Certificate expired 30 days ago
        let expired_date = NaiveDate::from_ymd_opt(2020, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &security_headers,
            &Some("CN=example.com".to_string()),
            &Some("CN=Let's Encrypt".to_string()),
            &Some(expired_date),
            &None,
        );

        assert!(warnings.contains(&SecurityWarning::InvalidCertificate));
    }

    #[test]
    fn test_analyze_security_self_signed_certificate() {
        let security_headers = HashMap::new();

        // Certificate valid in the future
        let future_date = NaiveDate::from_ymd_opt(2030, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();

        // Subject == Issuer means self-signed
        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &security_headers,
            &Some("CN=example.com".to_string()),
            &Some("CN=example.com".to_string()), // Same as subject = self-signed
            &Some(future_date),
            &None,
        );

        assert!(warnings.contains(&SecurityWarning::InvalidCertificate));
    }

    #[test]
    fn test_analyze_security_valid_certificate() {
        let security_headers = HashMap::new();

        // Certificate valid in the future
        let future_date = NaiveDate::from_ymd_opt(2030, 1, 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &security_headers,
            &Some("CN=example.com".to_string()),
            &Some("CN=Let's Encrypt Authority X3".to_string()),
            &Some(future_date),
            &None,
        );

        // Should not have invalid certificate warning
        assert!(!warnings.contains(&SecurityWarning::InvalidCertificate));
    }

    #[test]
    fn test_analyze_security_https_no_cert_info() {
        let security_headers = HashMap::new();

        // HTTPS but no certificate info (extraction failed)
        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &security_headers,
            &None, // No certificate info
            &None,
            &None,
            &None,
        );

        // Should warn about invalid certificate (couldn't extract)
        assert!(warnings.contains(&SecurityWarning::InvalidCertificate));
    }

    #[test]
    fn test_analyze_security_case_insensitive_headers() {
        let mut security_headers = HashMap::new();
        // Headers with different casing
        security_headers.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=31536000".to_string(),
        );
        security_headers.insert(
            "Content-Security-Policy".to_string(),
            "default-src 'self'".to_string(),
        );
        security_headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
        security_headers.insert("X-Frame-Options".to_string(), "DENY".to_string());

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &security_headers,
            &None,
            &None,
            &None,
            &None,
        );

        // Should not warn about missing headers (case-insensitive matching)
        assert!(!warnings.contains(&SecurityWarning::MissingHsts));
        assert!(!warnings.contains(&SecurityWarning::MissingCsp));
        assert!(!warnings.contains(&SecurityWarning::MissingContentTypeOptions));
        assert!(!warnings.contains(&SecurityWarning::MissingFrameOptions));
    }
}
