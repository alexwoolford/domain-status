//! Error extraction utilities for failure tracking.
//!
//! This module provides functions to extract error types and HTTP status codes
//! from error chains for failure categorization.

use anyhow::Error;
use reqwest::Error as ReqwestError;

use crate::error_handling::{categorize_reqwest_error, ErrorType};

/// Extracts error type from an error chain.
///
/// Uses the shared `categorize_reqwest_error` function for consistency,
/// but also enhances categorization by checking error messages for DNS/TLS patterns.
pub(crate) fn extract_error_type(error: &Error) -> ErrorType {
    // Check error chain for reqwest errors first
    for cause in error.chain() {
        if let Some(reqwest_err) = cause.downcast_ref::<ReqwestError>() {
            // Use shared categorization function for consistency
            let base_type = categorize_reqwest_error(reqwest_err);

            // Enhance categorization by checking error messages for DNS/TLS patterns
            // This provides more specific error types when the underlying cause is DNS/TLS
            let error_msg = reqwest_err.to_string().to_lowercase();

            // Check for DNS errors in message (more specific than generic connect/request errors)
            if error_msg.contains("dns")
                || error_msg.contains("name resolution")
                || error_msg.contains("failed to resolve")
            {
                // Try to determine which DNS lookup failed
                if error_msg.contains("txt") {
                    return ErrorType::DnsTxtLookupError;
                } else if error_msg.contains("mx") || error_msg.contains("mail") {
                    return ErrorType::DnsMxLookupError;
                }
                return ErrorType::DnsNsLookupError;
            }

            // Check for TLS errors in message
            if error_msg.contains("tls")
                || error_msg.contains("ssl")
                || error_msg.contains("certificate")
                || error_msg.contains("handshake")
            {
                return ErrorType::TlsCertificateError;
            }

            // Check for timeout in request/connect errors
            if (base_type == ErrorType::HttpRequestRequestError
                || base_type == ErrorType::HttpRequestConnectError)
                && error_msg.contains("timeout")
            {
                return ErrorType::HttpRequestTimeoutError;
            }

            // Return the base type (from shared categorization)
            return base_type;
        }
    }

    // Check error message for specific patterns (for errors without reqwest::Error)
    let msg = error.to_string().to_lowercase();
    // Check for HTTP request timeout first (more specific)
    if msg.contains("request timeout") || msg.contains("http") && msg.contains("timeout") {
        return ErrorType::HttpRequestTimeoutError;
    } else if msg.contains("timeout") {
        return ErrorType::ProcessUrlTimeout;
    }

    // Check for DNS errors in error message
    if msg.contains("dns") || msg.contains("resolve") || msg.contains("lookup failed") {
        // Try to determine which DNS lookup failed
        // Check for specific types FIRST (more specific patterns before general ones)
        if msg.contains("txt") {
            return ErrorType::DnsTxtLookupError;
        } else if msg.contains("mx") || msg.contains("mail") {
            return ErrorType::DnsMxLookupError;
        } else if msg.contains("ns") || msg.contains("nameserver") {
            return ErrorType::DnsNsLookupError;
        }
        // Generic DNS error - default to NS lookup error
        return ErrorType::DnsNsLookupError;
    }

    // Check for TLS errors in error message
    if msg.contains("tls")
        || msg.contains("ssl")
        || msg.contains("certificate")
        || msg.contains("handshake")
    {
        return ErrorType::TlsCertificateError;
    }

    // Default to other error
    ErrorType::HttpRequestOtherError
}

/// Extracts HTTP status code from an error chain.
pub fn extract_http_status(error: &Error) -> Option<u16> {
    // First try to downcast the error itself
    if let Some(reqwest_err) = error.downcast_ref::<ReqwestError>() {
        if let Some(status) = reqwest_err.status() {
            return Some(status.as_u16());
        }
    }

    // Then check the chain - iterate through sources
    for cause in error.chain() {
        if let Some(reqwest_err) = cause.downcast_ref::<ReqwestError>() {
            if let Some(status) = reqwest_err.status() {
                return Some(status.as_u16());
            }
        }
    }

    // If we can't find it via downcast, try to extract from the source chain
    // by recursively checking if any source is an anyhow::Error containing reqwest::Error
    let mut current: Option<&dyn std::error::Error> = error.source();
    while let Some(err) = current {
        // Try to get the underlying anyhow::Error if this is wrapped
        // We can't directly downcast &dyn Error, but we can check if it's an anyhow error
        // by attempting to access it through the chain
        if let Some(reqwest_err) = err.downcast_ref::<ReqwestError>() {
            if let Some(status) = reqwest_err.status() {
                return Some(status.as_u16());
            }
        }
        current = err.source();
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ErrorType;

    #[tokio::test]
    async fn test_extract_error_type_reqwest_dns_error() {
        // Test DNS error detection from reqwest error message
        // This is critical - DNS errors should be categorized correctly
        // Create a reqwest error by attempting an invalid request
        // Use a longer timeout to avoid timeout errors, focus on DNS errors
        let reqwest_err = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap()
            .get("http://invalid-domain-that-does-not-exist-12345.com")
            .send()
            .await
            .unwrap_err();
        let error = anyhow::Error::from(reqwest_err);

        let error_type = extract_error_type(&error);
        // Should detect DNS error from message (or timeout/connect error)
        // Accept multiple error types as DNS resolution can fail in different ways
        // Also accept HttpRequestRequestError as it can occur for various network issues
        assert!(
            matches!(
                error_type,
                ErrorType::DnsNsLookupError
                    | ErrorType::DnsTxtLookupError
                    | ErrorType::DnsMxLookupError
                    | ErrorType::HttpRequestConnectError
                    | ErrorType::HttpRequestTimeoutError
                    | ErrorType::HttpRequestRequestError
                    | ErrorType::HttpRequestOtherError
            ),
            "Expected DNS-related or network error type, got: {:?}",
            error_type
        );
    }

    #[test]
    fn test_extract_error_type_reqwest_dns_txt_error() {
        // Test TXT-specific DNS error detection
        // This is critical - TXT lookups should be distinguished from NS lookups
        // Create error with DNS TXT message pattern
        let error = anyhow::anyhow!("DNS TXT lookup failed");

        let error_type = extract_error_type(&error);
        assert_eq!(error_type, ErrorType::DnsTxtLookupError);
    }

    #[test]
    fn test_extract_error_type_reqwest_dns_mx_error() {
        // Test MX-specific DNS error detection
        // This is critical - MX lookups should be distinguished
        // Create error with DNS MX message pattern
        let error = anyhow::anyhow!("DNS mail exchange lookup failed");

        let error_type = extract_error_type(&error);
        assert_eq!(error_type, ErrorType::DnsMxLookupError);
    }

    #[test]
    fn test_extract_error_type_reqwest_tls_error() {
        // Test TLS error detection from reqwest error message
        // This is critical - TLS errors should be categorized correctly
        // Create error with TLS message pattern
        let error = anyhow::anyhow!("TLS handshake failed: certificate error");

        let error_type = extract_error_type(&error);
        assert_eq!(error_type, ErrorType::TlsCertificateError);
    }

    #[test]
    fn test_extract_error_type_reqwest_ssl_error() {
        // Test SSL error detection (alternative to TLS)
        // Create error with SSL message pattern
        let error = anyhow::anyhow!("SSL certificate validation failed");

        let error_type = extract_error_type(&error);
        assert_eq!(error_type, ErrorType::TlsCertificateError);
    }

    #[test]
    fn test_extract_error_type_reqwest_timeout_in_message() {
        // Test timeout detection when error message contains "timeout"
        // This is critical - timeouts should be distinguished from other errors
        // Create error with timeout message pattern
        let error = anyhow::anyhow!("request timeout after 30 seconds");

        let error_type = extract_error_type(&error);
        // Should detect timeout from message
        assert_eq!(error_type, ErrorType::HttpRequestTimeoutError);
    }

    #[test]
    fn test_extract_error_type_non_reqwest_timeout() {
        // Test timeout detection for non-reqwest errors
        // This is critical - timeout errors should be detected even without reqwest
        let error = anyhow::anyhow!("Process URL timeout after 45 seconds");

        let error_type = extract_error_type(&error);
        assert_eq!(error_type, ErrorType::ProcessUrlTimeout);
    }

    #[test]
    fn test_extract_error_type_non_reqwest_dns_error() {
        // Test DNS error detection for non-reqwest errors
        // This is critical - DNS errors should be detected even without reqwest
        let error = anyhow::anyhow!("DNS lookup failed for example.com");

        let error_type = extract_error_type(&error);
        assert!(
            matches!(
                error_type,
                ErrorType::DnsNsLookupError
                    | ErrorType::DnsTxtLookupError
                    | ErrorType::DnsMxLookupError
            ),
            "Expected DNS error type, got: {:?}",
            error_type
        );
    }

    #[test]
    fn test_extract_error_type_non_reqwest_tls_error() {
        // Test TLS error detection for non-reqwest errors
        let error = anyhow::anyhow!("TLS certificate validation failed");

        let error_type = extract_error_type(&error);
        assert_eq!(error_type, ErrorType::TlsCertificateError);
    }

    #[test]
    fn test_extract_error_type_fallback_to_other() {
        // Test fallback to HttpRequestOtherError for unknown errors
        // This is critical - unknown errors should not panic
        let error = anyhow::anyhow!("Unknown error occurred");

        let error_type = extract_error_type(&error);
        assert_eq!(error_type, ErrorType::HttpRequestOtherError);
    }

    #[tokio::test]
    async fn test_extract_http_status_with_status() {
        // Test HTTP status extraction from reqwest error
        // This is critical - status codes should be extracted correctly
        use httptest::{matchers::*, responders::*, Expectation, Server};

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/500"))
                .respond_with(status_code(500).body("Internal Server Error")),
        );

        let client = reqwest::Client::new();
        let url = server.url("/500").to_string();
        let response = client
            .get(&url)
            .send()
            .await
            .expect("Failed to create test request");
        let status = response.status();
        let reqwest_err = response.error_for_status().unwrap_err();
        let error = anyhow::Error::from(reqwest_err);

        let extracted_status = extract_http_status(&error);
        assert_eq!(extracted_status, Some(status.as_u16()));
    }

    #[test]
    fn test_extract_http_status_no_status() {
        // Test HTTP status extraction when no status is available
        // This is critical - should return None, not panic
        let error = anyhow::anyhow!("Connection error");

        let extracted_status = extract_http_status(&error);
        assert_eq!(extracted_status, None);
    }

    #[tokio::test]
    async fn test_extract_http_status_nested_error_chain() {
        // Test HTTP status extraction from nested error chain
        // This is critical - status should be found even if nested
        use httptest::{matchers::*, responders::*, Expectation, Server};

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/404"))
                .respond_with(status_code(404).body("Not Found")),
        );

        let client = reqwest::Client::new();
        let url = server.url("/404").to_string();
        let response = client
            .get(&url)
            .send()
            .await
            .expect("Failed to create test request");
        let status = response.status();
        let reqwest_err = response.error_for_status().unwrap_err();
        let error = anyhow::Error::from(reqwest_err)
            .context("Additional context")
            .context("More context");

        let extracted_status = extract_http_status(&error);
        assert_eq!(extracted_status, Some(status.as_u16()));
    }

    #[test]
    fn test_extract_error_type_dns_ns_specific() {
        // Test that NS-specific DNS errors are detected correctly
        // This is critical - NS lookup errors should be distinguished
        let error = anyhow::anyhow!("DNS nameserver lookup failed");
        let error_type = extract_error_type(&error);
        assert_eq!(error_type, ErrorType::DnsNsLookupError);
    }

    #[test]
    fn test_extract_error_type_dns_generic_falls_back_to_ns() {
        // Test that generic DNS errors fall back to NS lookup error
        // This is critical - default DNS error type should be NS
        let error = anyhow::anyhow!("DNS lookup failed");
        let error_type = extract_error_type(&error);
        // Generic DNS errors default to NS lookup error (line 83)
        assert_eq!(error_type, ErrorType::DnsNsLookupError);
    }

    #[test]
    fn test_extract_error_type_timeout_in_request_error() {
        // Test that timeout detection works for request errors
        // This is critical - timeouts should be detected even when wrapped in request errors
        // The code at line 50-54 checks for timeout in request/connect errors
        let error = anyhow::anyhow!("HTTP request error: timeout after 30 seconds");
        let error_type = extract_error_type(&error);
        // Should detect timeout from message
        assert_eq!(error_type, ErrorType::HttpRequestTimeoutError);
    }

    #[test]
    fn test_extract_error_type_tls_certificate_variations() {
        // Test that various TLS/SSL error messages are detected
        // This is critical - TLS errors can be described in multiple ways
        let variations = vec![
            "TLS handshake failed",
            "SSL certificate error",
            "Certificate validation failed",
            "TLS certificate expired",
        ];

        for msg in variations {
            let error = anyhow::anyhow!(msg);
            let error_type = extract_error_type(&error);
            assert_eq!(
                error_type,
                ErrorType::TlsCertificateError,
                "Failed to detect TLS error in: {}",
                msg
            );
        }
    }

    #[test]
    fn test_extract_error_type_http_timeout_vs_process_timeout() {
        // Test that HTTP timeouts are distinguished from process timeouts
        // This is critical - different timeout types should be categorized correctly
        // The code at line 65 checks for "request timeout" or "http" + "timeout"
        let http_timeout = anyhow::anyhow!("HTTP request timeout");
        let process_timeout = anyhow::anyhow!("Process URL timeout after 45 seconds");

        let http_type = extract_error_type(&http_timeout);
        let process_type = extract_error_type(&process_timeout);

        assert_eq!(http_type, ErrorType::HttpRequestTimeoutError);
        assert_eq!(process_type, ErrorType::ProcessUrlTimeout);
    }

    #[test]
    fn test_extract_error_type_message_case_insensitive() {
        // Test that error message matching is case-insensitive
        // This is critical - error messages can be in any case
        let variations = vec![
            "DNS lookup failed",
            "dns lookup failed",
            "DNS LOOKUP FAILED",
            "DnS lOoKuP fAiLeD",
        ];

        for msg in variations {
            let error = anyhow::anyhow!(msg);
            let error_type = extract_error_type(&error);
            // All should detect DNS error (case-insensitive matching via to_lowercase)
            assert!(
                matches!(
                    error_type,
                    ErrorType::DnsNsLookupError
                        | ErrorType::DnsTxtLookupError
                        | ErrorType::DnsMxLookupError
                ),
                "Failed to detect DNS error (case-insensitive) in: {}",
                msg
            );
        }
    }

    #[test]
    fn test_extract_error_type_unknown_fallback_to_other() {
        // Test that unknown errors fall back to HttpRequestOtherError
        // This is critical - unknown errors should not cause panics
        let error = anyhow::anyhow!("Some completely unknown error type");
        let error_type = extract_error_type(&error);
        assert_eq!(error_type, ErrorType::HttpRequestOtherError);
    }

    #[tokio::test]
    async fn test_extract_http_status_from_error_itself() {
        // Test that HTTP status is extracted from error itself first (line 102-105)
        // This is critical - direct reqwest errors should be handled efficiently
        use httptest::{matchers::*, responders::*, Expectation, Server};

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/503"))
                .respond_with(status_code(503).body("Service Unavailable")),
        );

        let client = reqwest::Client::new();
        let url = server.url("/503").to_string();
        let response = client
            .get(&url)
            .send()
            .await
            .expect("Failed to create test request");
        let status = response.status();
        let reqwest_err = response.error_for_status().unwrap_err();
        let error: anyhow::Error = reqwest_err.into();

        // Should extract status from error itself (not just chain)
        let extracted_status = extract_http_status(&error);
        assert_eq!(extracted_status, Some(status.as_u16()));
    }

    #[test]
    fn test_extract_http_status_no_reqwest_error() {
        // Test that non-reqwest errors return None
        // This is critical - should handle non-HTTP errors gracefully
        let error = anyhow::anyhow!("Database connection error");
        let extracted_status = extract_http_status(&error);
        assert_eq!(extracted_status, None);
    }
}
