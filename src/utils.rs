use anyhow::{Error, Result};
use hickory_resolver::TokioAsyncResolver;
use publicsuffix::List;
use sqlx::SqlitePool;
use std::sync::Arc;

use crate::error_handling::{get_retry_strategy, ErrorStats};
use crate::http::handle_http_request;

/// Processes a single URL with retry logic.
///
/// This is the main entry point for processing a URL. It handles retries
/// with exponential backoff and orchestrates the HTTP request and response handling.
///
/// # Arguments
///
/// * `url` - The URL to process
/// * `client` - HTTP client for making requests
/// * `redirect_client` - HTTP client with redirects disabled
/// * `pool` - Database connection pool
/// * `extractor` - Public Suffix List extractor
/// * `resolver` - DNS resolver
/// * `error_stats` - Error statistics tracker
///
/// # Errors
///
/// Returns an error if all retry attempts fail.
pub async fn process_url(
    url: String,
    client: Arc<reqwest::Client>,
    redirect_client: Arc<reqwest::Client>,
    pool: Arc<SqlitePool>,
    extractor: Arc<List>,
    resolver: Arc<TokioAsyncResolver>,
    error_stats: Arc<ErrorStats>,
) -> Result<(), Error> {
    log::debug!("Starting process for URL: {url}");

    let retry_strategy = get_retry_strategy();
    let start_time = std::time::Instant::now();

    let result = tokio_retry::Retry::spawn(retry_strategy, || {
        let client = client.clone();
        let redirect_client = redirect_client.clone();
        let url = url.clone();
        let pool = pool.clone();
        let extractor = extractor.clone();
        let error_stats = error_stats.clone();
        let resolver = resolver.clone();

        async move {
            handle_http_request(
                &client,
                &redirect_client,
                &url,
                &pool,
                &extractor,
                &resolver,
                &error_stats,
                start_time,
            )
            .await
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
