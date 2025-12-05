//! URL processing orchestration with retry logic.

use anyhow::{Error, Result};
use std::sync::Arc;

use crate::error_handling::get_retry_strategy;
use crate::fetch::{handle_http_request, ProcessingContext};

use super::retry::is_retriable_error;

/// Result of processing a URL, including retry count.
///
/// This struct is returned by `process_url()` to provide both the processing result
/// and information about retry attempts made.
#[derive(Debug)]
pub struct ProcessUrlResult {
    /// The result of processing the URL.
    ///
    /// - `Ok(())` indicates successful processing
    /// - `Err(error)` indicates the URL processing failed
    pub result: Result<(), Error>,
    /// The number of retry attempts made (not including the initial attempt).
    ///
    /// This value is tracked manually and may not be 100% accurate in all edge cases,
    /// but provides a good approximation for monitoring and debugging purposes.
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
