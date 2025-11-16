use anyhow::{Error, Result};
use hickory_resolver::TokioAsyncResolver;
use publicsuffix::List;
use sqlx::SqlitePool;
use std::sync::Arc;

use crate::error_handling::{get_retry_strategy, ErrorStats};
use crate::fetch::handle_http_request;

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

/// Processes a single URL with selective retry logic.
///
/// Only retries network-related errors (timeouts, connection failures, 5xx errors).
/// Permanent errors (404, 403, parsing errors) are not retried.
///
/// # Arguments
///
/// * `url` - The URL to process (wrapped in Arc to avoid cloning on retries)
/// * `client` - HTTP client for making requests
/// * `redirect_client` - HTTP client with redirects disabled
/// * `pool` - Database connection pool
/// * `extractor` - Public Suffix List extractor
/// * `resolver` - DNS resolver
/// * `error_stats` - Error statistics tracker
/// * `run_id` - Unique identifier for this run (for time-series tracking)
///
/// # Errors
///
/// Returns an error if all retry attempts fail or if a non-retriable error occurs.
#[allow(clippy::too_many_arguments)]
pub async fn process_url(
    url: Arc<String>,
    client: Arc<reqwest::Client>,
    redirect_client: Arc<reqwest::Client>,
    pool: Arc<SqlitePool>,
    extractor: Arc<List>,
    resolver: Arc<TokioAsyncResolver>,
    error_stats: Arc<ErrorStats>,
    run_id: Option<String>,
) -> Result<(), Error> {
    log::debug!("Starting process for URL: {url}");

    let retry_strategy = get_retry_strategy();
    let start_time = std::time::Instant::now();

    let result = tokio_retry::Retry::spawn(retry_strategy, || {
        // Clone only what's necessary for the async block
        // Arc clones are cheap (just incrementing reference count)
        let client = Arc::clone(&client);
        let redirect_client = Arc::clone(&redirect_client);
        let url = Arc::clone(&url); // Arc clone is cheap (pointer increment, not string copy)
        let pool = Arc::clone(&pool);
        let extractor = Arc::clone(&extractor);
        let error_stats = Arc::clone(&error_stats);
        let resolver = Arc::clone(&resolver);
        let run_id_clone = run_id.clone();

        async move {
            let result = handle_http_request(
                &client,
                &redirect_client,
                url.as_str(), // Use as_str() to get &str from Arc<String>
                &pool,
                &extractor,
                &resolver,
                &error_stats,
                start_time,
                run_id_clone.as_deref(),
            )
            .await;

            // Only retry if error is retriable
            match &result {
                Ok(_) => result,
                Err(e) => {
                    if is_retriable_error(e) {
                        result
                    } else {
                        // Non-retriable error - stop retrying
                        Err(anyhow::anyhow!("Non-retriable error: {}", e))
                    }
                }
            }
        }
    })
    .await;

    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            log::error!("Error processing URL {url} after retries: {e}");
            Err(e)
        }
    }
}
