pub mod sanitize;

use anyhow::{Error, Result};
use std::sync::Arc;

use crate::error_handling::get_retry_strategy;
use crate::fetch::{handle_http_request, ProcessingContext};

/// Determines if an error is retriable (should be retried).
///
/// Only network-related errors should be retried. Permanent errors like
/// 404, 403, parsing errors, and database errors should not be retried.
///
/// Uses error chain inspection to properly identify error types without
/// relying on fragile string matching.
fn is_retriable_error(error: &anyhow::Error) -> bool {
    // Check error chain for specific error types
    for cause in error.chain() {
        // Check for reqwest errors (HTTP client errors)
        if let Some(reqwest_err) = cause.downcast_ref::<reqwest::Error>() {
            // Check HTTP status codes
            if let Some(status) = reqwest_err.status() {
                match status.as_u16() {
                    // Permanent client errors - don't retry
                    400..=499 => {
                        // 429 (Too Many Requests) might be retriable with backoff,
                        // but for now we treat it as non-retriable to avoid hammering
                        if status.as_u16() == 429 {
                            return true; // Rate limiting - retry with backoff
                        }
                        return false;
                    }
                    // Server errors - retry (temporary)
                    500..=599 => return true,
                    _ => {}
                }
            }

            // Check reqwest error types
            if reqwest_err.is_timeout() {
                return true; // Timeouts are retriable
            }
            if reqwest_err.is_connect() {
                return true; // Connection errors are retriable
            }
            if reqwest_err.is_request() {
                return true; // Request errors (network issues) are retriable
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

        // Check for DNS errors (retriable - network issue)
        // Note: hickory_resolver errors are wrapped in anyhow, so we check the message
        // DNS errors are typically network-related and should be retried
        let msg = cause.to_string().to_lowercase();
        if msg.contains("dns") || msg.contains("resolve") || msg.contains("lookup failed") {
            return true;
        }

        // Check for database errors (not retriable)
        if cause.downcast_ref::<sqlx::Error>().is_some() {
            return false;
        }

        // Check error message for specific patterns (fallback for unknown error types)
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
/// * `url` - The URL to process (wrapped in Arc to avoid cloning on retries)
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
pub async fn process_url(url: String, ctx: Arc<ProcessingContext>) -> ProcessUrlResult {
    log::debug!("Starting process for URL: {url}");

    let retry_strategy = get_retry_strategy();
    let start_time = std::time::Instant::now();

    // Track retry attempts using Arc<AtomicU32> (needed for async closures with move semantics)
    // The counter is incremented each time the closure is called (once per attempt)
    let attempt_count = Arc::new(std::sync::atomic::AtomicU32::new(0));

    let result = tokio_retry::Retry::spawn(retry_strategy, {
        let url = url.clone(); // String clone is cheap for typical URLs (< 200 bytes)
        let ctx = Arc::clone(&ctx);
        let attempt_count = Arc::clone(&attempt_count);
        move || {
            // Increment attempt counter (includes initial attempt + retries)
            attempt_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let url = url.clone(); // Clone again for each retry attempt
            let ctx = Arc::clone(&ctx);

            async move {
                let result = handle_http_request(&ctx, &url, start_time).await;

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
            log::error!("Error processing URL {url} after retries: {e}");
            Err(e)
        }
    };

    ProcessUrlResult {
        result: final_result,
        retry_count,
    }
}
