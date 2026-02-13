//! Security analysis and warning detection.
//!
//! This module analyzes HTTP responses and TLS configurations to identify
//! security issues and best practice violations:
//! - Missing HTTPS
//! - Weak TLS versions
//! - Missing security headers (HSTS, CSP, etc.)
//!
//! Warnings are stored in the database for later analysis.

mod analysis;
mod types;
mod url_validation;

pub use analysis::analyze_security;
pub use types::SecurityWarning;
pub use url_validation::validate_url_safe;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::TlsVersion;
    use std::collections::HashMap;

    #[test]
    fn test_is_weak_tls() {
        assert!(!TlsVersion::Tls13.is_weak());
        assert!(!TlsVersion::Tls12.is_weak());
        assert!(TlsVersion::Tls11.is_weak());
        assert!(TlsVersion::Tls10.is_weak());
        assert!(TlsVersion::Ssl30.is_weak());
        assert!(TlsVersion::Unknown.is_weak()); // SSLv2 -> Unknown
    }

    #[test]
    fn test_analyze_security_no_https() {
        let headers = HashMap::new();
        let warnings = analyze_security(
            "http://example.com",
            &None,
            &headers,
            &None,
            &None,
            &None,
            &None,
        );
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
            &Some(TlsVersion::Tls11),
            &headers,
            &None,
            &None,
            &None,
            &None,
        );
        assert!(warnings.contains(&SecurityWarning::WeakTls));
    }

    #[test]
    fn test_analyze_security_missing_headers() {
        let headers = HashMap::new();
        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &headers,
            &None,
            &None,
            &None,
            &None,
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

        // Provide valid certificate info (not expired, not self-signed)
        let valid_date = chrono::Utc::now()
            .naive_utc()
            .checked_add_signed(chrono::Duration::days(365))
            .unwrap();

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &headers,
            &Some("CN=example.com".to_string()),
            &Some("CN=Let's Encrypt".to_string()),
            &Some(valid_date),
            &None,
        );
        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn test_is_weak_tls_edge_cases() {
        // Secure versions
        assert!(!TlsVersion::Tls13.is_weak());
        assert!(!TlsVersion::Tls12.is_weak());

        // Weak versions
        assert!(TlsVersion::Tls11.is_weak());
        assert!(TlsVersion::Tls10.is_weak());
        assert!(TlsVersion::Ssl30.is_weak());
        assert!(TlsVersion::Unknown.is_weak());
    }

    #[test]
    fn test_analyze_security_missing_single_header() {
        // Test each missing header individually
        let mut headers = HashMap::new();

        // Missing HSTS only
        headers.insert(
            "content-security-policy".to_string(),
            "default-src 'self'".to_string(),
        );
        headers.insert("x-content-type-options".to_string(), "nosniff".to_string());
        headers.insert("x-frame-options".to_string(), "DENY".to_string());

        // Provide valid certificate info
        let valid_date = chrono::Utc::now()
            .naive_utc()
            .checked_add_signed(chrono::Duration::days(365))
            .unwrap();

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &headers,
            &Some("CN=example.com".to_string()),
            &Some("CN=Let's Encrypt".to_string()),
            &Some(valid_date),
            &None,
        );
        assert_eq!(warnings.len(), 1);
        assert!(warnings.contains(&SecurityWarning::MissingHsts));

        // Missing CSP only
        headers.clear();
        headers.insert(
            "strict-transport-security".to_string(),
            "max-age=31536000".to_string(),
        );
        headers.insert("x-content-type-options".to_string(), "nosniff".to_string());
        headers.insert("x-frame-options".to_string(), "DENY".to_string());

        // Provide valid certificate info
        let valid_date = chrono::Utc::now()
            .naive_utc()
            .checked_add_signed(chrono::Duration::days(365))
            .unwrap();

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &headers,
            &Some("CN=example.com".to_string()),
            &Some("CN=Let's Encrypt".to_string()),
            &Some(valid_date),
            &None,
        );
        assert_eq!(warnings.len(), 1);
        assert!(warnings.contains(&SecurityWarning::MissingCsp));

        // Missing X-Content-Type-Options only
        headers.clear();
        headers.insert(
            "strict-transport-security".to_string(),
            "max-age=31536000".to_string(),
        );
        headers.insert(
            "content-security-policy".to_string(),
            "default-src 'self'".to_string(),
        );
        headers.insert("x-frame-options".to_string(), "DENY".to_string());

        // Provide valid certificate info
        let valid_date = chrono::Utc::now()
            .naive_utc()
            .checked_add_signed(chrono::Duration::days(365))
            .unwrap();

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &headers,
            &Some("CN=example.com".to_string()),
            &Some("CN=Let's Encrypt".to_string()),
            &Some(valid_date),
            &None,
        );
        assert_eq!(warnings.len(), 1);
        assert!(warnings.contains(&SecurityWarning::MissingContentTypeOptions));

        // Missing X-Frame-Options only
        headers.clear();
        headers.insert(
            "strict-transport-security".to_string(),
            "max-age=31536000".to_string(),
        );
        headers.insert(
            "content-security-policy".to_string(),
            "default-src 'self'".to_string(),
        );
        headers.insert("x-content-type-options".to_string(), "nosniff".to_string());

        // Provide valid certificate info
        let valid_date = chrono::Utc::now()
            .naive_utc()
            .checked_add_signed(chrono::Duration::days(365))
            .unwrap();

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &headers,
            &Some("CN=example.com".to_string()),
            &Some("CN=Let's Encrypt".to_string()),
            &Some(valid_date),
            &None,
        );
        assert_eq!(warnings.len(), 1);
        assert!(warnings.contains(&SecurityWarning::MissingFrameOptions));
    }

    #[test]
    fn test_analyze_security_case_insensitive_headers() {
        // Test that header matching is case-insensitive
        let mut headers = HashMap::new();
        headers.insert(
            "Strict-Transport-Security".to_string(),
            "max-age=31536000".to_string(),
        );
        headers.insert(
            "Content-Security-Policy".to_string(),
            "default-src 'self'".to_string(),
        );
        headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
        headers.insert("X-Frame-Options".to_string(), "DENY".to_string());

        // Provide valid certificate info
        let valid_date = chrono::Utc::now()
            .naive_utc()
            .checked_add_signed(chrono::Duration::days(365))
            .unwrap();

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &headers,
            &Some("CN=example.com".to_string()),
            &Some("CN=Let's Encrypt".to_string()),
            &Some(valid_date),
            &None,
        );
        // All headers present (case-insensitive match) - no warnings
        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn test_analyze_security_http_returns_early() {
        // HTTP URLs should return early (only NoHttps warning)
        let mut headers = HashMap::new();
        headers.insert(
            "strict-transport-security".to_string(),
            "max-age=31536000".to_string(),
        );

        let warnings = analyze_security(
            "http://example.com",
            &Some(TlsVersion::Tls11),
            &headers,
            &None,
            &None,
            &None,
            &None,
        );

        // Should only have NoHttps warning, not WeakTls or missing headers
        assert_eq!(warnings.len(), 1);
        assert!(warnings.contains(&SecurityWarning::NoHttps));
        assert!(!warnings.contains(&SecurityWarning::WeakTls));
    }

    #[test]
    fn test_analyze_security_no_tls_version() {
        // HTTPS without TLS version info
        let headers = HashMap::new();
        let warnings = analyze_security(
            "https://example.com",
            &None,
            &headers,
            &None,
            &None,
            &None,
            &None,
        );

        // Should have missing headers warnings, but not WeakTls (no version info)
        assert!(warnings.contains(&SecurityWarning::MissingHsts));
        assert!(warnings.contains(&SecurityWarning::MissingCsp));
        assert!(!warnings.contains(&SecurityWarning::WeakTls));
    }

    #[test]
    fn test_analyze_security_weak_tls_with_headers() {
        // Weak TLS but all headers present
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

        // Provide valid certificate info
        let valid_date = chrono::Utc::now()
            .naive_utc()
            .checked_add_signed(chrono::Duration::days(365))
            .unwrap();

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls11),
            &headers,
            &Some("CN=example.com".to_string()),
            &Some("CN=Let's Encrypt".to_string()),
            &Some(valid_date),
            &None,
        );

        // Should only have WeakTls warning
        assert_eq!(warnings.len(), 1);
        assert!(warnings.contains(&SecurityWarning::WeakTls));
    }

    #[test]
    fn test_analyze_security_all_warnings() {
        // HTTP with weak TLS and no headers (if it were HTTPS)
        // But HTTP returns early, so test HTTPS with weak TLS and no headers
        let headers = HashMap::new();

        // Provide valid certificate info
        let valid_date = chrono::Utc::now()
            .naive_utc()
            .checked_add_signed(chrono::Duration::days(365))
            .unwrap();

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls10),
            &headers,
            &Some("CN=example.com".to_string()),
            &Some("CN=Let's Encrypt".to_string()),
            &Some(valid_date),
            &None,
        );

        // Should have WeakTls + all missing headers (but NOT InvalidCertificate since cert is valid)
        assert!(warnings.contains(&SecurityWarning::WeakTls));
        assert!(warnings.contains(&SecurityWarning::MissingHsts));
        assert!(warnings.contains(&SecurityWarning::MissingCsp));
        assert!(warnings.contains(&SecurityWarning::MissingContentTypeOptions));
        assert!(warnings.contains(&SecurityWarning::MissingFrameOptions));
        assert!(!warnings.contains(&SecurityWarning::InvalidCertificate));
        assert_eq!(warnings.len(), 5);
    }

    #[test]
    fn test_analyze_security_expired_certificate() {
        // Expired certificate should generate InvalidCertificate warning
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

        // Certificate expired yesterday
        let expired_date = chrono::Utc::now()
            .naive_utc()
            .checked_sub_signed(chrono::Duration::days(1))
            .unwrap();

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &headers,
            &Some("CN=example.com".to_string()),
            &Some("CN=Let's Encrypt".to_string()),
            &Some(expired_date),
            &None,
        );

        assert!(warnings.contains(&SecurityWarning::InvalidCertificate));
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn test_analyze_security_self_signed_certificate() {
        // Self-signed certificate (subject == issuer) should generate InvalidCertificate warning
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

        // Certificate valid for 1 year from now
        let valid_date = chrono::Utc::now()
            .naive_utc()
            .checked_add_signed(chrono::Duration::days(365))
            .unwrap();

        let subject = "CN=example.com";
        let issuer = "CN=example.com"; // Same as subject (self-signed)

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &headers,
            &Some(subject.to_string()),
            &Some(issuer.to_string()),
            &Some(valid_date),
            &None,
        );

        assert!(warnings.contains(&SecurityWarning::InvalidCertificate));
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn test_analyze_security_self_signed_certificate_with_whitespace() {
        // Self-signed certificate with whitespace differences should still be detected
        let mut headers = HashMap::new();
        headers.insert(
            "strict-transport-security".to_string(),
            "max-age=31536000".to_string(),
        );

        let valid_date = chrono::Utc::now()
            .naive_utc()
            .checked_add_signed(chrono::Duration::days(365))
            .unwrap();

        let subject = "  CN=example.com  "; // With whitespace
        let issuer = "CN=example.com"; // Without whitespace

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &headers,
            &Some(subject.to_string()),
            &Some(issuer.to_string()),
            &Some(valid_date),
            &None,
        );

        // Should detect as self-signed (normalized comparison)
        assert!(warnings.contains(&SecurityWarning::InvalidCertificate));
    }

    #[test]
    fn test_analyze_security_self_signed_certificate_case_insensitive() {
        // Self-signed certificate with case differences should still be detected
        let mut headers = HashMap::new();
        headers.insert(
            "strict-transport-security".to_string(),
            "max-age=31536000".to_string(),
        );

        let valid_date = chrono::Utc::now()
            .naive_utc()
            .checked_add_signed(chrono::Duration::days(365))
            .unwrap();

        let subject = "CN=Example.com"; // Mixed case
        let issuer = "cn=example.com"; // Lowercase

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &headers,
            &Some(subject.to_string()),
            &Some(issuer.to_string()),
            &Some(valid_date),
            &None,
        );

        // Should detect as self-signed (case-insensitive comparison)
        assert!(warnings.contains(&SecurityWarning::InvalidCertificate));
    }

    #[test]
    fn test_analyze_security_valid_certificate() {
        // Valid certificate (not expired, not self-signed) should not generate InvalidCertificate warning
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

        // Certificate valid for 1 year from now
        let valid_date = chrono::Utc::now()
            .naive_utc()
            .checked_add_signed(chrono::Duration::days(365))
            .unwrap();

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &headers,
            &Some("CN=example.com".to_string()),
            &Some("CN=Let's Encrypt".to_string()), // Different issuer (not self-signed)
            &Some(valid_date),
            &None,
        );

        // Should have no warnings (all good)
        assert!(!warnings.contains(&SecurityWarning::InvalidCertificate));
        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn test_analyze_security_tls_extraction_failure() {
        // If TLS extraction fails (no certificate info) on HTTPS, should generate InvalidCertificate warning
        let headers = HashMap::new();

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &headers,
            &None, // No certificate subject (extraction failed)
            &None, // No certificate issuer
            &None, // No certificate expiration
            &None,
        );

        // Should have InvalidCertificate warning due to extraction failure
        assert!(warnings.contains(&SecurityWarning::InvalidCertificate));
        // Also should have missing headers warnings
        assert!(warnings.contains(&SecurityWarning::MissingHsts));
    }

    #[test]
    fn test_analyze_security_tls_extraction_failure_http() {
        // HTTP sites should not check certificates (returns early)
        let headers = HashMap::new();

        let warnings = analyze_security(
            "http://example.com",
            &None,
            &headers,
            &None, // No certificate info (expected for HTTP)
            &None,
            &None,
            &None,
        );

        // Should only have NoHttps warning, not InvalidCertificate
        assert_eq!(warnings.len(), 1);
        assert!(warnings.contains(&SecurityWarning::NoHttps));
        assert!(!warnings.contains(&SecurityWarning::InvalidCertificate));
    }

    #[test]
    fn test_analyze_security_expired_and_self_signed() {
        // Certificate that is both expired AND self-signed should only generate one InvalidCertificate warning
        let headers = HashMap::new();

        let expired_date = chrono::Utc::now()
            .naive_utc()
            .checked_sub_signed(chrono::Duration::days(1))
            .unwrap();

        let subject = "CN=example.com";
        let issuer = "CN=example.com"; // Self-signed

        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &headers,
            &Some(subject.to_string()),
            &Some(issuer.to_string()),
            &Some(expired_date),
            &None,
        );

        // Should have InvalidCertificate warning (only once, not duplicated)
        assert!(warnings.contains(&SecurityWarning::InvalidCertificate));
        let invalid_cert_count = warnings
            .iter()
            .filter(|w| matches!(w, SecurityWarning::InvalidCertificate))
            .count();
        assert_eq!(invalid_cert_count, 1);
    }

    #[test]
    fn test_analyze_security_partial_certificate_info() {
        // If we have some certificate info but not all required fields (subject, issuer, valid_to),
        // we can't check validity, so should treat as extraction failure
        let headers = HashMap::new();

        let valid_date = chrono::Utc::now()
            .naive_utc()
            .checked_add_signed(chrono::Duration::days(365))
            .unwrap();

        // Have subject and valid_to, but missing issuer
        let warnings = analyze_security(
            "https://example.com",
            &Some(TlsVersion::Tls13),
            &headers,
            &Some("CN=example.com".to_string()),
            &None, // Missing issuer - can't check validity
            &Some(valid_date),
            &None,
        );

        // Should have InvalidCertificate warning because we can't verify the certificate
        // (missing required field means extraction was incomplete)
        assert!(warnings.contains(&SecurityWarning::InvalidCertificate));
    }
}
