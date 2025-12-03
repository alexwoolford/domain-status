//! Failure context structures and operations.
//!
//! This module provides structures and functions for attaching and extracting
//! structured failure context from errors.

use anyhow::Error;

/// Failure context passed directly to avoid fragile string parsing.
#[derive(Debug, Clone, Default)]
pub struct FailureContext {
    pub final_url: Option<String>,
    pub redirect_chain: Vec<String>,
    pub response_headers: Vec<(String, String)>,
    pub request_headers: Vec<(String, String)>,
}

/// Custom error type that carries failure context.
///
/// This allows us to pass structured failure context through the error chain
/// without relying on fragile string parsing.
#[derive(Debug)]
pub struct FailureContextError {
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
    error.context(FailureContextError { context })
}

/// Extracts failure context from an error chain.
///
/// Looks for a `FailureContextError` in the error chain and extracts its context.
/// Returns empty context if no structured context is found (simpler and more robust).
pub fn extract_failure_context(error: &Error) -> FailureContext {
    // Look for structured context in error chain
    for cause in error.chain() {
        if let Some(context_err) = cause.downcast_ref::<FailureContextError>() {
            return context_err.context.clone();
        }
    }

    // No structured context found - return empty context
    // This is simpler and more robust than fragile string parsing
    // All error paths should attach structured context using attach_failure_context()
    FailureContext::default()
}
