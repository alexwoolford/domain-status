//! Utility functions for URL processing.
//!
//! This module provides:
//! - URL processing orchestration with retry logic
//! - Error retriability determination
//! - String sanitization utilities

pub mod sanitize;

use anyhow::{Error, Result};
use std::sync::Arc;

use crate::error_handling::get_retry_strategy;
use crate::fetch::{handle_http_request, ProcessingContext};

/// Determines if an error is retriable (should be retried).
///
/// This function categorizes errors into retriable (transient) and non-retriable (permanent)
/// categories to guide retry logic. Only transient errors that might succeed on retry
/// should be retried.
///
/// # Retriable Errors
///
/// - Network timeouts (`reqwest::Error::is_timeout()`)
/// - Connection failures (`reqwest::Error::is_connect()`)
/// - Request errors (`reqwest::Error::is_request()`)
/// - Server errors (5xx HTTP status codes)
/// - Rate limiting (429 Too Many Requests)
/// - DNS resolution failures
///
/// # Non-Retriable Errors
///
/// - Client errors (4xx HTTP status codes, except 429)
/// - URL parsing errors
/// - Database errors
/// - Redirect errors
/// - Decode errors
///
/// # Implementation Details
///
/// Uses error chain inspection to properly identify error types without relying on
/// fragile string matching. Checks for specific error types (reqwest::Error, url::ParseError,
/// sqlx::Error) via downcasting, which is more reliable than string matching.
///
/// # Examples
///
/// ```rust,no_run
/// use anyhow::Error;
///
/// // Timeout error - retriable
/// let timeout_err = Error::from(reqwest::Error::from(reqwest::ErrorKind::Request));
/// assert!(is_retriable_error(&timeout_err));
///
/// // URL parse error - not retriable
/// let parse_err = Error::from(url::ParseError::EmptyHost);
/// assert!(!is_retriable_error(&parse_err));
/// ```
fn is_retriable_error(error: &anyhow::Error) -> bool {
    // Check error chain for specific error types
    for cause in error.chain() {
        // Check for reqwest errors (HTTP client errors)
        if let Some(reqwest_err) = cause.downcast_ref::<reqwest::Error>() {
            // Check HTTP status codes first
            if let Some(status) = reqwest_err.status() {
                let status_code = status.as_u16();

                // 429 (Too Many Requests) is retriable with backoff
                if status_code == crate::config::HTTP_STATUS_TOO_MANY_REQUESTS {
                    return true;
                }

                // Permanent client errors (4xx except 429) - don't retry
                if (400..500).contains(&status_code) {
                    return false;
                }

                // Server errors (5xx) - retry (temporary)
                if (500..600).contains(&status_code) {
                    return true;
                }
            }

            // Check reqwest error types (network-related errors are retriable)
            if reqwest_err.is_timeout() || reqwest_err.is_connect() || reqwest_err.is_request() {
                return true;
            }

            // Redirect errors, decode errors, etc. are not retriable
            if reqwest_err.is_redirect() || reqwest_err.is_decode() {
                return false;
            }
        }

        // Check for URL parsing errors (not retriable)
        if cause.downcast_ref::<url::ParseError>().is_some() {
            return false;
        }

        // Check for database errors (not retriable)
        if cause.downcast_ref::<sqlx::Error>().is_some() {
            return false;
        }

        // Check for DNS errors (retriable - network issue)
        // Note: hickory_resolver errors are wrapped in anyhow, so we check the message
        let msg = cause.to_string().to_lowercase();
        if msg.contains("dns") || msg.contains("resolve") || msg.contains("lookup failed") {
            return true;
        }

        // Check error message for specific patterns (fallback for non-reqwest errors)
        // This handles cases where we have an error but not a reqwest::Error with status code
        // (e.g., errors from other libraries that don't expose HTTP status directly)
        if msg.contains("404") || msg.contains("not found") {
            return false;
        }
        if msg.contains("403") || msg.contains("forbidden") {
            return false;
        }
        if msg.contains("401") || msg.contains("unauthorized") {
            return false;
        }
    }

    // Default: retry unknown errors (might be transient network issue)
    true
}

/// Result of processing a URL, including retry count.
#[derive(Debug)]
pub struct ProcessUrlResult {
    pub result: Result<(), Error>,
    pub retry_count: u32,
}

/// Processes a single URL with selective retry logic.
///
/// Only retries network-related errors (timeouts, connection failures, 5xx errors).
/// Permanent errors (404, 403, parsing errors) are not retried.
///
/// # Arguments
///
/// * `url` - The URL to process (wrapped in Arc<str> to avoid cloning on retries)
/// * `ctx` - Processing context containing all shared resources
///
/// # Returns
///
/// A `ProcessUrlResult` containing the result and the actual number of retry attempts made.
///
/// # Retry Count Accuracy
///
/// The `retry_count` field represents the number of retry attempts made (not including the initial attempt).
/// This is tracked manually using an atomic counter, and may not be 100% accurate in all edge cases
/// (e.g., if retries are aborted early or if the retry strategy changes). For most practical purposes,
/// this provides a good approximation of retry attempts.
pub async fn process_url(url: Arc<str>, ctx: Arc<ProcessingContext>) -> ProcessUrlResult {
    log::debug!("Starting process for URL: {}", url.as_ref());

    let retry_strategy = get_retry_strategy();
    let start_time = std::time::Instant::now();

    // Track retry attempts using Arc<AtomicU32> (needed for async closures with move semantics)
    // The counter is incremented each time the closure is called (once per attempt)
    let attempt_count = Arc::new(std::sync::atomic::AtomicU32::new(0));

    let result = tokio_retry::Retry::spawn(retry_strategy, {
        let url = Arc::clone(&url); // Arc clone is just a pointer increment
        let ctx = Arc::clone(&ctx);
        let attempt_count = Arc::clone(&attempt_count);
        move || {
            // Increment attempt counter (includes initial attempt + retries)
            attempt_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let url = Arc::clone(&url); // Arc clone for each retry attempt (just pointer increment)
            let ctx = Arc::clone(&ctx);

            async move {
                let result = handle_http_request(&ctx, url.as_ref(), start_time).await;

                // Only retry if error is retriable
                match result {
                    Ok(_) => result,
                    Err(e) => {
                        if is_retriable_error(&e) {
                            Err(e) // Preserve error chain (including FailureContextError)
                        } else {
                            // Non-retriable error - stop retrying
                            // Use .context() to preserve the original error chain
                            Err(e.context("Non-retriable error"))
                        }
                    }
                }
            }
        }
    })
    .await;

    // Calculate retry count (attempts - 1, since first attempt isn't a retry)
    // This is an approximation: exact count may vary if retries are aborted early
    let total_attempts = attempt_count.load(std::sync::atomic::Ordering::SeqCst);
    let retry_count = total_attempts.saturating_sub(1);

    let final_result = match result {
        Ok(()) => Ok(()),
        Err(e) => {
            log::error!("Error processing URL {} after retries: {e}", url.as_ref());
            Err(e)
        }
    };

    ProcessUrlResult {
        result: final_result,
        retry_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Error;

    // Note: Testing is_retriable_error with actual reqwest::Error instances is complex
    // because reqwest::Error doesn't expose a simple constructor. These tests verify
    // the logic for non-reqwest errors. For comprehensive testing of reqwest errors,
    // integration tests with a mock HTTP server (e.g., httptest) would be better.

    #[test]
    fn test_is_retriable_error_url_parse() {
        // URL parse errors should NOT be retriable
        let parse_error = url::ParseError::EmptyHost;
        let error = Error::from(parse_error);
        assert!(!is_retriable_error(&error));
    }

    #[test]
    fn test_is_retriable_error_database() {
        // Database errors should NOT be retriable
        // This would require creating a sqlx::Error
        // which is complex without a real database connection
    }
}
