//! Failure context structures and operations.
//!
//! This module provides structures and functions for attaching and extracting
//! structured failure context from errors.

use anyhow::Error;

/// Failure context passed directly to avoid fragile string parsing.
///
/// This struct contains structured information about a failed HTTP request,
/// including the final URL, redirect chain, and headers. This context is
/// attached to errors to provide detailed debugging information without
/// relying on fragile string parsing.
#[derive(Debug, Clone, Default)]
pub struct FailureContext {
    /// The final URL after following redirects (if available).
    pub final_url: Option<String>,
    /// The complete redirect chain from initial to final URL.
    ///
    /// Each element in the vector represents one redirect hop.
    pub redirect_chain: Vec<String>,
    /// HTTP response headers received from the server.
    ///
    /// Stored as a vector of (name, value) tuples.
    pub response_headers: Vec<(String, String)>,
    /// HTTP request headers sent to the server.
    ///
    /// Stored as a vector of (name, value) tuples.
    pub request_headers: Vec<(String, String)>,
}

/// Custom error type that carries failure context.
///
/// This allows us to pass structured failure context through the error chain
/// without relying on fragile string parsing. The context is automatically
/// included in the error message when displayed.
#[derive(Debug)]
pub struct FailureContextError {
    /// The failure context containing URL, redirect chain, and headers.
    pub context: FailureContext,
}

impl std::fmt::Display for FailureContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Provide more useful error message with context details
        if let Some(ref final_url) = self.context.final_url {
            if !self.context.redirect_chain.is_empty() {
                write!(
                    f,
                    "Request failed for {} (redirected from {} via {} hop(s))",
                    final_url,
                    self.context.redirect_chain.first().unwrap_or(final_url),
                    self.context.redirect_chain.len().saturating_sub(1)
                )
            } else {
                write!(f, "Request failed for {}", final_url)
            }
        } else {
            write!(f, "Request failed (no final URL available)")
        }
    }
}

impl std::error::Error for FailureContextError {}

/// Helper function to attach failure context to an error.
///
/// This provides a consistent way to attach structured failure context
/// to errors throughout the codebase, reducing duplication.
pub fn attach_failure_context(error: anyhow::Error, context: FailureContext) -> anyhow::Error {
    // Make FailureContextError the root error, with the original error as context
    // This allows us to downcast the root error to FailureContextError
    let context_error = anyhow::Error::from(FailureContextError { context });
    context_error.context(error)
}

/// Extracts failure context from an error chain.
///
/// Looks for a `FailureContextError` in the error chain and extracts its context.
/// Returns empty context if no structured context is found (simpler and more robust).
pub fn extract_failure_context(error: &Error) -> FailureContext {
    // Try to downcast the error itself first
    // When we attach context using attach_failure_context, FailureContextError is the root
    if let Some(context_err) = error.downcast_ref::<FailureContextError>() {
        return context_err.context.clone();
    }

    // No structured context found - return empty context
    // Note: If context was attached using .context() directly (not attach_failure_context),
    // it becomes a source in the chain and we can't extract it with downcast_ref.
    // All context should be attached using attach_failure_context() to ensure extractability.
    FailureContext::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attach_failure_context() {
        // Test that failure context is correctly attached to errors
        // This is critical - context must be preserved through error chains
        let context = FailureContext {
            final_url: Some("https://example.com".to_string()),
            redirect_chain: vec!["https://example.org".to_string()],
            response_headers: vec![("content-type".to_string(), "text/html".to_string())],
            request_headers: vec![("user-agent".to_string(), "test".to_string())],
        };

        let original_error = anyhow::anyhow!("HTTP request failed");
        let error_with_context = attach_failure_context(original_error, context.clone());

        // Verify context can be extracted
        let extracted = extract_failure_context(&error_with_context);
        assert_eq!(extracted.final_url, context.final_url);
        assert_eq!(extracted.redirect_chain, context.redirect_chain);
        assert_eq!(extracted.response_headers, context.response_headers);
        assert_eq!(extracted.request_headers, context.request_headers);
    }

    #[test]
    fn test_attach_failure_context_preserves_original_error() {
        // Test that original error message is preserved
        // This is critical - context should enhance, not replace, error messages
        let context = FailureContext {
            final_url: Some("https://example.com".to_string()),
            redirect_chain: vec![],
            response_headers: vec![],
            request_headers: vec![],
        };

        let original_error = anyhow::anyhow!("Connection timeout");
        let error_with_context = attach_failure_context(original_error, context);

        // Original error message should still be in the chain
        // When context is attached, the error message format includes the context
        // but the original message should still be present somewhere in the chain
        let error_msg = error_with_context.to_string();
        // The error message might be formatted as "Request failed for ..." with context,
        // but the original "Connection timeout" should still be in the chain
        // Check both the full message and iterate through the chain
        let has_original = error_msg.contains("Connection timeout")
            || error_msg.contains("timeout")
            || error_with_context
                .chain()
                .any(|e| e.to_string().contains("Connection timeout"));
        assert!(
            has_original,
            "Original error message not found in chain. Error: {}",
            error_msg
        );
    }

    #[test]
    fn test_extract_failure_context_nested_chain() {
        // Test context extraction from nested error chain
        // This is critical - context should be found even if deeply nested
        let context = FailureContext {
            final_url: Some("https://example.com".to_string()),
            redirect_chain: vec!["https://example.org".to_string()],
            response_headers: vec![],
            request_headers: vec![],
        };

        // Use attach_failure_context to ensure context is extractable
        // Then add additional context layers
        let error = attach_failure_context(
            anyhow::anyhow!("Root error").context("Middle context"),
            context.clone(),
        )
        .context("Top context");

        let extracted = extract_failure_context(&error);
        assert_eq!(extracted.final_url, context.final_url);
        assert_eq!(extracted.redirect_chain, context.redirect_chain);
    }

    #[test]
    fn test_extract_failure_context_empty_context() {
        // Test extraction when no context is attached
        // This is critical - should return empty context, not panic
        let error = anyhow::anyhow!("Simple error");

        let extracted = extract_failure_context(&error);
        assert_eq!(extracted.final_url, None);
        assert_eq!(extracted.redirect_chain, Vec::<String>::new());
        assert_eq!(extracted.response_headers, Vec::<(String, String)>::new());
        assert_eq!(extracted.request_headers, Vec::<(String, String)>::new());
    }

    #[test]
    fn test_failure_context_error_display_with_redirects() {
        // Test FailureContextError Display implementation with redirects
        // This is critical - error messages should be informative
        let context = FailureContext {
            final_url: Some("https://www.example.com".to_string()),
            redirect_chain: vec![
                "https://example.com".to_string(),
                "https://www.example.com".to_string(),
            ],
            response_headers: vec![],
            request_headers: vec![],
        };

        let context_error = FailureContextError { context };
        let display_msg = context_error.to_string();

        assert!(display_msg.contains("www.example.com"));
        assert!(display_msg.contains("hop"));
    }

    #[test]
    fn test_failure_context_error_display_without_redirects() {
        // Test FailureContextError Display without redirects
        let context = FailureContext {
            final_url: Some("https://example.com".to_string()),
            redirect_chain: vec![],
            response_headers: vec![],
            request_headers: vec![],
        };

        let context_error = FailureContextError { context };
        let display_msg = context_error.to_string();

        assert!(display_msg.contains("example.com"));
        assert!(!display_msg.contains("hop"));
    }

    #[test]
    fn test_failure_context_error_display_no_final_url() {
        // Test FailureContextError Display without final URL
        // This is critical - should handle missing final_url gracefully
        let context = FailureContext {
            final_url: None,
            redirect_chain: vec![],
            response_headers: vec![],
            request_headers: vec![],
        };

        let context_error = FailureContextError { context };
        let display_msg = context_error.to_string();

        assert!(display_msg.contains("no final URL available"));
    }

    #[test]
    fn test_failure_context_default() {
        // Test FailureContext::default() creates empty context
        // This is critical - default should be safe to use
        let context = FailureContext::default();

        assert_eq!(context.final_url, None);
        assert_eq!(context.redirect_chain, Vec::<String>::new());
        assert_eq!(context.response_headers, Vec::<(String, String)>::new());
        assert_eq!(context.request_headers, Vec::<(String, String)>::new());
    }
}
