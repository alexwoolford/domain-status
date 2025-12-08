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
    use std::collections::HashMap;

    #[test]
    fn test_is_weak_tls() {
        assert!(!analysis::is_weak_tls("TLSv1.3"));
        assert!(!analysis::is_weak_tls("TLSv1.2"));
        assert!(!analysis::is_weak_tls("TLSv1_3")); // Format used by rustls
        assert!(!analysis::is_weak_tls("TLSv1_2")); // Format used by rustls
        assert!(!analysis::is_weak_tls("TLS 1.3"));
        assert!(!analysis::is_weak_tls("TLS 1.2"));
        assert!(analysis::is_weak_tls("TLSv1.1"));
        assert!(analysis::is_weak_tls("TLSv1.0"));
        assert!(analysis::is_weak_tls("SSLv3"));
        assert!(analysis::is_weak_tls("SSLv2"));
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

    #[test]
    fn test_is_weak_tls_edge_cases() {
        // Test various TLS version formats
        assert!(!analysis::is_weak_tls("TLSv1.3"));
        assert!(!analysis::is_weak_tls("TLSv1.2"));
        assert!(!analysis::is_weak_tls("tlsv1.3")); // Lowercase
        assert!(!analysis::is_weak_tls("TLS 1.3")); // With space
        assert!(!analysis::is_weak_tls("TLS1.3")); // No 'v'
        assert!(!analysis::is_weak_tls("tls1.2")); // Lowercase, no 'v'

        // Weak versions
        assert!(analysis::is_weak_tls("TLSv1.1"));
        assert!(analysis::is_weak_tls("TLSv1.0"));
        assert!(analysis::is_weak_tls("tls1.1")); // Lowercase
        assert!(analysis::is_weak_tls("TLS 1.1")); // With space
        assert!(analysis::is_weak_tls("SSLv3"));
        assert!(analysis::is_weak_tls("SSLv2"));
        assert!(analysis::is_weak_tls("ssl3")); // Lowercase
        assert!(analysis::is_weak_tls("")); // Empty string is weak
        assert!(analysis::is_weak_tls("unknown")); // Unknown version is weak
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
        let warnings = analyze_security(
            "https://example.com",
            &Some("TLSv1.3".to_string()),
            &headers,
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
        let warnings = analyze_security(
            "https://example.com",
            &Some("TLSv1.3".to_string()),
            &headers,
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
        let warnings = analyze_security(
            "https://example.com",
            &Some("TLSv1.3".to_string()),
            &headers,
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
        let warnings = analyze_security(
            "https://example.com",
            &Some("TLSv1.3".to_string()),
            &headers,
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

        let warnings = analyze_security(
            "https://example.com",
            &Some("TLSv1.3".to_string()),
            &headers,
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

        let warnings =
            analyze_security("http://example.com", &Some("TLSv1.1".to_string()), &headers);

        // Should only have NoHttps warning, not WeakTls or missing headers
        assert_eq!(warnings.len(), 1);
        assert!(warnings.contains(&SecurityWarning::NoHttps));
        assert!(!warnings.contains(&SecurityWarning::WeakTls));
    }

    #[test]
    fn test_analyze_security_no_tls_version() {
        // HTTPS without TLS version info
        let headers = HashMap::new();
        let warnings = analyze_security("https://example.com", &None, &headers);

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

        let warnings = analyze_security(
            "https://example.com",
            &Some("TLSv1.1".to_string()),
            &headers,
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
        let warnings = analyze_security(
            "https://example.com",
            &Some("TLSv1.0".to_string()),
            &headers,
        );

        // Should have WeakTls + all missing headers
        assert!(warnings.contains(&SecurityWarning::WeakTls));
        assert!(warnings.contains(&SecurityWarning::MissingHsts));
        assert!(warnings.contains(&SecurityWarning::MissingCsp));
        assert!(warnings.contains(&SecurityWarning::MissingContentTypeOptions));
        assert!(warnings.contains(&SecurityWarning::MissingFrameOptions));
        assert_eq!(warnings.len(), 5);
    }
}
