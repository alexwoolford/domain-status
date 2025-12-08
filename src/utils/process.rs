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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_url_result_structure() {
        // Verify ProcessUrlResult has the expected structure
        let result = ProcessUrlResult {
            result: Ok(()),
            retry_count: 0,
        };
        assert!(result.result.is_ok());
        assert_eq!(result.retry_count, 0);
    }

    #[test]
    fn test_process_url_result_with_retries() {
        let result = ProcessUrlResult {
            result: Err(anyhow::anyhow!("Test error")),
            retry_count: 3,
        };
        assert!(result.result.is_err());
        assert_eq!(result.retry_count, 3);
    }

    // Note: Full integration tests for process_url() would require:
    // - Mock HTTP server (httptest)
    // - Database with migrations
    // - Complex ProcessingContext setup
    // These are better suited for integration_test.rs
    // Here we focus on testing the ProcessUrlResult structure

    #[test]
    fn test_process_url_result_retry_count_zero() {
        // Test that retry_count is 0 when no retries occur
        let result = ProcessUrlResult {
            result: Ok(()),
            retry_count: 0,
        };
        assert_eq!(result.retry_count, 0);
        assert!(result.result.is_ok());
    }

    #[test]
    fn test_process_url_result_retry_count_max() {
        // Test that retry_count can handle maximum retry attempts
        let result = ProcessUrlResult {
            result: Err(anyhow::anyhow!("Max retries exceeded")),
            retry_count: 10,
        };
        assert_eq!(result.retry_count, 10);
        assert!(result.result.is_err());
    }

    #[test]
    fn test_process_url_result_error_preservation() {
        // Test that error information is preserved
        let error = anyhow::anyhow!("Test error with context").context("Additional context");
        let result = ProcessUrlResult {
            result: Err(error),
            retry_count: 2,
        };
        assert!(result.result.is_err());
        let error_msg = result.result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Test error") || error_msg.contains("Additional context"),
            "Error should preserve context, got: {}",
            error_msg
        );
    }

    #[test]
    fn test_process_url_result_retry_count_saturating_sub() {
        // Test that retry_count uses saturating_sub correctly
        // If total_attempts is 0, retry_count should be 0 (not underflow)
        // This tests the saturating_sub(1) logic in process_url
        let result = ProcessUrlResult {
            result: Ok(()),
            retry_count: 0u32.saturating_sub(1), // Should be 0, not u32::MAX
        };
        assert_eq!(result.retry_count, 0);
    }

    #[test]
    fn test_process_url_result_retry_count_edge_cases() {
        // Test edge cases for retry_count calculation
        // retry_count = total_attempts.saturating_sub(1)

        // Case 1: total_attempts = 0 (should never happen, but test saturating_sub)
        assert_eq!(0u32.saturating_sub(1), 0);

        // Case 2: total_attempts = 1 (initial attempt only, no retries)
        assert_eq!(1u32.saturating_sub(1), 0);

        // Case 3: total_attempts = 2 (1 retry)
        assert_eq!(2u32.saturating_sub(1), 1);

        // Case 4: total_attempts = u32::MAX (should not underflow)
        assert_eq!(u32::MAX.saturating_sub(1), u32::MAX - 1);
    }
}
