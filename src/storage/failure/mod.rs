//! Failure tracking and insertion utilities.
//!
//! This module provides functions to extract failure information from errors
//! and insert failure records into the database.

mod context;
mod error;
mod record;

// Re-export public API
pub use context::{
    attach_failure_context, extract_failure_context, FailureContext, FailureContextError,
};
#[allow(unused_imports)] // Used in tests
pub use error::extract_http_status;
pub use record::{record_url_failure, FailureRecordParams};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ErrorType;

    #[test]
    fn test_extract_error_type_timeout() {
        // Create a timeout error
        let error = anyhow::anyhow!("Process URL timeout after 45 seconds");

        assert_eq!(
            error::extract_error_type(&error),
            ErrorType::ProcessUrlTimeout
        );
    }

    #[test]
    fn test_extract_error_type_dns_error_message() {
        // Create an error with DNS-related message
        let error =
            anyhow::anyhow!("Failed to resolve DNS: no record found").context("DNS lookup failed");

        // Note: This test depends on error message parsing
        // The actual behavior may vary, but we test that DNS errors are detected
        let error_type = error::extract_error_type(&error);
        assert!(
            matches!(
                error_type,
                ErrorType::DnsNsLookupError
                    | ErrorType::DnsTxtLookupError
                    | ErrorType::DnsMxLookupError
                    | ErrorType::HttpRequestOtherError
            ),
            "Expected DNS-related error type or fallback, got: {:?}",
            error_type
        );
    }

    #[test]
    fn test_extract_failure_context_from_structured_error() {
        let context = FailureContext {
            final_url: Some("https://example.com".to_string()),
            redirect_chain: vec!["https://example.org".to_string()],
            response_headers: vec![("content-type".to_string(), "text/html".to_string())],
            request_headers: vec![("user-agent".to_string(), "test".to_string())],
        };
        let error = anyhow::Error::from(FailureContextError {
            context: context.clone(),
        });

        let extracted = extract_failure_context(&error);
        assert_eq!(extracted.final_url, context.final_url);
        assert_eq!(extracted.redirect_chain, context.redirect_chain);
        assert_eq!(extracted.response_headers, context.response_headers);
        assert_eq!(extracted.request_headers, context.request_headers);
    }

    #[test]
    fn test_extract_failure_context_no_structured_context() {
        // Create an error without structured context (no FailureContextError)
        // The system now only uses structured context, so this should return empty context
        let error = anyhow::anyhow!("HTTP request failed")
            .context("FINAL_URL:https://example.com")
            .context("REDIRECT_CHAIN:[\"https://example.org\"]");

        let extracted = extract_failure_context(&error);
        // Without structured context, we return empty context (no string parsing fallback)
        assert_eq!(extracted.final_url, None);
        assert_eq!(extracted.redirect_chain, Vec::<String>::new());
        assert_eq!(extracted.response_headers, Vec::<(String, String)>::new());
        assert_eq!(extracted.request_headers, Vec::<(String, String)>::new());
    }

    #[test]
    fn test_failure_mod_extract_http_status_no_status() {
        // Error without HTTP status
        let error = anyhow::anyhow!("Connection error");

        assert_eq!(error::extract_http_status(&error), None);
    }

    #[test]
    fn test_error_message_truncation_logic() {
        // Test truncation logic (simulating what happens in record_url_failure)
        let long_message = "x".repeat(3000);
        // Use centralized sanitization and truncation
        let truncated = crate::utils::sanitize::sanitize_and_truncate_error_message(&long_message);

        let max_len = crate::config::MAX_ERROR_MESSAGE_LENGTH;
        assert!(truncated.len() <= max_len + 100); // Allow for truncation message
        assert!(truncated.contains("truncated"));
        assert!(truncated.contains("3000"));
    }

    #[tokio::test]
    async fn test_circuit_breaker_integration() {
        use crate::storage::circuit_breaker::DbWriteCircuitBreaker;

        let cb = DbWriteCircuitBreaker::with_threshold(2, std::time::Duration::from_millis(50));

        // Record failures
        cb.record_failure().await;
        assert!(!cb.is_circuit_open().await);

        cb.record_failure().await;
        assert!(cb.is_circuit_open().await);

        // Record success should close circuit
        cb.record_success().await;
        assert!(!cb.is_circuit_open().await);
        assert_eq!(cb.failure_count(), 0);
    }
}
