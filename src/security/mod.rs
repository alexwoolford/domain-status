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

pub use analysis::analyze_security;
pub use types::SecurityWarning;

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
}

