//! URL processing orchestration with retry logic.

use anyhow::{Error, Result};
use std::sync::Arc;

use crate::error_handling::get_retry_strategy;
use crate::fetch::UrlProcessOutcome;
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
    pub result: Result<UrlProcessOutcome, Error>,
    /// The number of retry attempts made (not including the initial attempt).
    ///
    /// This value is tracked manually and may not be 100% accurate in all edge cases,
    /// but provides a good approximation for monitoring and debugging purposes.
    pub retry_count: u32,
}

async fn execute_with_retry<T, F, Fut>(
    mut operation: F,
    attempt_count: &Arc<std::sync::atomic::AtomicU32>,
    runtime_metrics: &crate::runtime_metrics::RuntimeMetrics,
) -> Result<T, Error>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, Error>>,
{
    let mut retry_strategy = get_retry_strategy();

    loop {
        attempt_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        match operation().await {
            Ok(value) => return Ok(value),
            Err(error) => {
                if !is_retriable_error(&error) {
                    runtime_metrics.record_non_retriable_failure();
                    return Err(error.context("Non-retriable error"));
                }

                let Some(delay) = retry_strategy.next() else {
                    return Err(error);
                };

                runtime_metrics.record_retry();
                tokio::time::sleep(delay).await;
            }
        }
    }
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

    // Track retry attempts using Arc<AtomicU32> (needed for async closures with move semantics)
    // The counter is incremented each time the closure is called (once per attempt)
    let attempt_count = Arc::new(std::sync::atomic::AtomicU32::new(0));

    let result = execute_with_retry(
        {
            let url = Arc::clone(&url); // Arc clone is just a pointer increment
            let ctx = Arc::clone(&ctx);
            move || {
                let url = Arc::clone(&url); // Arc clone for each retry attempt (just pointer increment)
                let ctx = Arc::clone(&ctx);
                // Start time per attempt so response_time_seconds reflects only this attempt,
                // not retry backoff sleep (avoids inflating metrics for retried requests).
                let start_time = std::time::Instant::now();
                async move { handle_http_request(&ctx, url.as_ref(), start_time).await }
            }
        },
        &attempt_count,
        ctx.config.runtime_metrics.as_ref(),
    )
    .await;

    // Calculate retry count (attempts - 1, since first attempt isn't a retry)
    // This is an approximation: exact count may vary if retries are aborted early
    let total_attempts = attempt_count.load(std::sync::atomic::Ordering::SeqCst);
    let retry_count = total_attempts.saturating_sub(1);

    let final_result = match result {
        Ok(outcome) => Ok(outcome),
        Err(e) => {
            log::error!(
                "Failed to process URL {} after {} retries: {}",
                url.as_ref(),
                retry_count,
                e
            );
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
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    fn retriable_error() -> anyhow::Error {
        anyhow::anyhow!("DNS lookup failed")
    }

    fn non_retriable_error() -> anyhow::Error {
        anyhow::anyhow!("404 not found")
    }

    #[tokio::test(start_paused = true)]
    async fn test_execute_with_retry_retries_transient_errors_until_success() {
        let attempt_count = Arc::new(AtomicU32::new(0));
        let remaining_failures = Arc::new(AtomicU32::new(2));
        let runtime_metrics = crate::runtime_metrics::RuntimeMetrics::default();

        let result = execute_with_retry(
            {
                let remaining_failures = Arc::clone(&remaining_failures);
                move || {
                    let remaining_failures = Arc::clone(&remaining_failures);
                    async move {
                        let remaining = remaining_failures.load(Ordering::SeqCst);
                        if remaining > 0 {
                            remaining_failures.fetch_sub(1, Ordering::SeqCst);
                            Err(retriable_error())
                        } else {
                            Ok(())
                        }
                    }
                }
            },
            &attempt_count,
            &runtime_metrics,
        );

        tokio::pin!(result);
        tokio::time::advance(Duration::from_secs(10)).await;

        result
            .await
            .expect("retriable error should eventually succeed");
        assert_eq!(attempt_count.load(Ordering::SeqCst), 3);
        assert_eq!(runtime_metrics.retried_requests(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn test_execute_with_retry_stops_immediately_for_terminal_errors() {
        let attempt_count = Arc::new(AtomicU32::new(0));

        let runtime_metrics = crate::runtime_metrics::RuntimeMetrics::default();
        let result = execute_with_retry(
            || async { Err::<(), anyhow::Error>(non_retriable_error()) },
            &attempt_count,
            &runtime_metrics,
        )
        .await
        .expect_err("terminal errors should not retry");

        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);
        assert!(result.to_string().contains("Non-retriable error"));
        assert_eq!(runtime_metrics.non_retriable_failures(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_execute_with_retry_returns_last_retriable_error_after_budget_exhausted() {
        let attempt_count = Arc::new(AtomicU32::new(0));

        let runtime_metrics = crate::runtime_metrics::RuntimeMetrics::default();
        let result = execute_with_retry(
            || async { Err::<(), anyhow::Error>(retriable_error()) },
            &attempt_count,
            &runtime_metrics,
        );

        tokio::pin!(result);
        tokio::time::advance(Duration::from_secs(60)).await;

        let error = result
            .await
            .expect_err("retriable errors should surface after retry budget is exhausted");

        assert!(error.to_string().contains("DNS lookup failed"));
        assert!(
            attempt_count.load(Ordering::SeqCst) > 1,
            "retry budget should allow multiple attempts"
        );
        assert!(runtime_metrics.retried_requests() > 0);
    }
}
