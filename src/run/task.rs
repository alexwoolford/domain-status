//! Per-URL task processing.
//!
//! This module contains the logic for processing a single URL, including
//! success/failure/timeout handling.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::config::{HTTP_STATUS_TOO_MANY_REQUESTS, RETRY_MAX_ATTEMPTS, URL_PROCESSING_TIMEOUT};
use crate::error_handling::ErrorType;
use crate::fetch::UrlProcessOutcome;
use crate::storage::failure::record_url_failure;
use crate::utils::ProcessUrlResult;

use super::invoke_progress_callback;
use super::resources::{ProgressCallback, UrlTaskParams};

/// Process a single URL task.
///
/// This function is spawned as a Tokio task for each URL. It handles:
/// - Rate limiting (if configured)
/// - URL processing with timeout
/// - Success/failure/timeout outcome handling
/// - Adaptive rate limiting feedback
///
/// # Arguments
///
/// * `params` - All parameters needed to process the URL
pub async fn process_url_task(params: UrlTaskParams) {
    let UrlTaskParams {
        url,
        ctx,
        permit: _permit, // Hold permit until task completes
        request_limiter,
        adaptive_limiter,
        per_domain_limiter,
        completed_urls,
        successful_urls,
        skipped_urls,
        failed_urls,
        total_urls_for_callback,
        progress_callback,
    } = params;

    // Acquire per-domain permit if enabled (before global rate limiter)
    let _domain_permit = if let Some(ref limiter) = per_domain_limiter {
        let domain_key = crate::per_domain_limiter::extract_domain_key(url.as_ref());
        match limiter.acquire(&domain_key).await {
            Ok(permit) => Some(permit),
            Err(_) => {
                log::warn!("Per-domain semaphore closed for {}, skipping", url.as_ref());
                None
            }
        }
    } else {
        None
    };

    // Apply rate limiting if configured
    if let Some(ref limiter) = request_limiter {
        limiter.acquire().await;
    }

    let process_start = std::time::Instant::now();
    let url_for_logging = Arc::clone(&url);

    // Process URL with timeout
    let result = tokio::time::timeout(
        URL_PROCESSING_TIMEOUT,
        crate::utils::process_url(url, ctx.clone()),
    )
    .await;

    match result {
        Ok(ProcessUrlResult {
            result: Ok(outcome),
            ..
        }) => {
            handle_success(
                &url_for_logging,
                outcome,
                &completed_urls,
                &successful_urls,
                &skipped_urls,
                &failed_urls,
                total_urls_for_callback,
                &progress_callback,
                adaptive_limiter.as_ref(),
            )
            .await;
        }
        Ok(ProcessUrlResult {
            result: Err(e),
            retry_count,
        }) => {
            handle_failure(
                &url_for_logging,
                e,
                retry_count,
                process_start,
                &ctx,
                &completed_urls,
                &failed_urls,
                total_urls_for_callback,
                &progress_callback,
                adaptive_limiter.as_ref(),
            )
            .await;
        }
        Err(_) => {
            handle_timeout(
                &url_for_logging,
                process_start,
                &ctx,
                &completed_urls,
                &failed_urls,
                total_urls_for_callback,
                &progress_callback,
                adaptive_limiter.as_ref(),
            )
            .await;
        }
    }
}

/// Handle successful URL processing.
#[allow(clippy::too_many_arguments)]
async fn handle_success(
    _url: &Arc<str>,
    outcome: UrlProcessOutcome,
    completed_urls: &Arc<std::sync::atomic::AtomicUsize>,
    successful_urls: &Arc<std::sync::atomic::AtomicUsize>,
    skipped_urls: &Arc<std::sync::atomic::AtomicUsize>,
    failed_urls: &Arc<std::sync::atomic::AtomicUsize>,
    total_urls_for_callback: usize,
    progress_callback: &ProgressCallback,
    adaptive_limiter: Option<&Arc<crate::adaptive_rate_limiter::AdaptiveRateLimiter>>,
) {
    completed_urls.fetch_add(1, Ordering::SeqCst);
    match outcome {
        UrlProcessOutcome::Inserted => {
            successful_urls.fetch_add(1, Ordering::SeqCst);
        }
        UrlProcessOutcome::Skipped => {
            skipped_urls.fetch_add(1, Ordering::SeqCst);
        }
    }
    invoke_progress_callback(
        progress_callback,
        completed_urls,
        failed_urls,
        total_urls_for_callback,
    );
    if let Some(adaptive) = adaptive_limiter {
        adaptive.record_success().await;
    }
}

/// Handle failed URL processing.
#[allow(clippy::too_many_arguments)]
async fn handle_failure(
    url: &Arc<str>,
    error: anyhow::Error,
    retry_count: u32,
    process_start: std::time::Instant,
    ctx: &Arc<crate::fetch::ProcessingContext>,
    completed_urls: &Arc<std::sync::atomic::AtomicUsize>,
    failed_urls: &Arc<std::sync::atomic::AtomicUsize>,
    total_urls_for_callback: usize,
    progress_callback: &ProgressCallback,
    adaptive_limiter: Option<&Arc<crate::adaptive_rate_limiter::AdaptiveRateLimiter>>,
) {
    failed_urls.fetch_add(1, Ordering::SeqCst);
    let elapsed = process_start.elapsed().as_secs_f64();
    invoke_progress_callback(
        progress_callback,
        completed_urls,
        failed_urls,
        total_urls_for_callback,
    );
    log::warn!("Failed to process URL {}: {error}", url.as_ref());

    let context = crate::storage::failure::extract_failure_context(&error);

    if let Err(record_err) = record_url_failure(crate::storage::failure::FailureRecordParams {
        pool: &ctx.db.pool,
        extractor: &ctx.network.extractor,
        url: url.as_ref(),
        error: &error,
        context,
        retry_count,
        elapsed_time: elapsed,
        run_id: ctx.config.run_id.as_deref(),
        circuit_breaker: Arc::clone(&ctx.db.circuit_breaker),
    })
    .await
    {
        log::warn!(
            "Failed to record failure for {}: {}",
            url.as_ref(),
            record_err
        );
    }

    // Check for rate limiting response
    if let Some(adaptive) = adaptive_limiter {
        let is_429 = error.chain().any(|cause| {
            if let Some(reqwest_err) = cause.downcast_ref::<reqwest::Error>() {
                reqwest_err
                    .status()
                    .map(|s| s.as_u16() == HTTP_STATUS_TOO_MANY_REQUESTS)
                    .unwrap_or(false)
            } else {
                false
            }
        });
        if is_429 {
            adaptive.record_rate_limited().await;
        }
    }
}

/// Handle URL processing timeout.
#[allow(clippy::too_many_arguments)]
async fn handle_timeout(
    url: &Arc<str>,
    process_start: std::time::Instant,
    ctx: &Arc<crate::fetch::ProcessingContext>,
    completed_urls: &Arc<std::sync::atomic::AtomicUsize>,
    failed_urls: &Arc<std::sync::atomic::AtomicUsize>,
    total_urls_for_callback: usize,
    progress_callback: &ProgressCallback,
    adaptive_limiter: Option<&Arc<crate::adaptive_rate_limiter::AdaptiveRateLimiter>>,
) {
    failed_urls.fetch_add(1, Ordering::SeqCst);
    let elapsed = process_start.elapsed().as_secs_f64();
    invoke_progress_callback(
        progress_callback,
        completed_urls,
        failed_urls,
        total_urls_for_callback,
    );
    log::warn!(
        "Failed to process URL {} (timeout after {}s)",
        url.as_ref(),
        URL_PROCESSING_TIMEOUT.as_secs()
    );
    let timeout_error = anyhow::anyhow!(
        "Process URL timeout after {} seconds for {}",
        URL_PROCESSING_TIMEOUT.as_secs(),
        url.as_ref()
    );

    let context = crate::storage::failure::FailureContext {
        final_url: None,
        redirect_chain: Vec::new(),
        response_headers: Vec::new(),
        request_headers: Vec::new(),
    };

    // SAFETY: Cast from usize to u32 is safe here.
    // RETRY_MAX_ATTEMPTS is a compile-time constant set to 3, which is well within
    // the range of u32 (0 to 4,294,967,295).
    #[allow(clippy::cast_possible_truncation)]
    if let Err(record_err) = record_url_failure(crate::storage::failure::FailureRecordParams {
        pool: &ctx.db.pool,
        extractor: &ctx.network.extractor,
        url: url.as_ref(),
        error: &timeout_error,
        context,
        retry_count: RETRY_MAX_ATTEMPTS as u32 - 1,
        elapsed_time: elapsed,
        run_id: ctx.config.run_id.as_deref(),
        circuit_breaker: Arc::clone(&ctx.db.circuit_breaker),
    })
    .await
    {
        log::warn!(
            "Failed to record timeout failure for {}: {}",
            url.as_ref(),
            record_err
        );
    }

    ctx.config
        .error_stats
        .increment_error(ErrorType::ProcessUrlTimeout);

    if let Some(adaptive) = adaptive_limiter {
        adaptive.record_timeout().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptive_rate_limiter::AdaptiveRateLimiter;
    use crate::error_handling::ProcessingStats;
    use crate::fetch::{ConfigContext, DatabaseContext, NetworkContext, ProcessingContext};
    use crate::storage::circuit_breaker::DbWriteCircuitBreaker;
    use crate::utils::TimingStats;
    use hickory_resolver::config::ResolverOpts;
    use hickory_resolver::TokioResolver;
    use std::sync::atomic::AtomicUsize;

    /// Builds a minimal `ProcessingContext` for task tests (in-memory DB, no migrations).
    /// `record_url_failure` will fail when inserting (tables not created) — use for
    /// testing "record failure failed" path.
    async fn minimal_ctx_without_migrations() -> Arc<ProcessingContext> {
        let client = Arc::new(reqwest::Client::builder().build().expect("test client"));
        let redirect_client = Arc::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("test redirect client"),
        );
        let extractor = Arc::new(psl::List);
        let resolver = Arc::new(
            TokioResolver::builder_tokio()
                .unwrap()
                .with_options(ResolverOpts::default())
                .build(),
        );
        let pool = Arc::new(
            sqlx::SqlitePool::connect("sqlite::memory:")
                .await
                .expect("test pool"),
        );
        let ctx = ProcessingContext::new(
            NetworkContext::new(client, redirect_client, extractor, resolver),
            DatabaseContext::new(pool, Arc::new(DbWriteCircuitBreaker::default())),
            ConfigContext::new(
                Arc::new(ProcessingStats::new()),
                Arc::new(TimingStats::new()),
                Some("run-1".to_string()),
                false,
                Arc::new(crate::runtime_metrics::RuntimeMetrics::default()),
            ),
        );
        Arc::new(ctx)
    }

    /// Builds a minimal `ProcessingContext` with migrations so `record_url_failure` can succeed.
    async fn minimal_ctx_with_migrations() -> Arc<ProcessingContext> {
        let pool = Arc::new(
            sqlx::SqlitePool::connect("sqlite::memory:")
                .await
                .expect("test pool"),
        );
        crate::storage::run_migrations(pool.as_ref())
            .await
            .expect("migrations");
        let client = Arc::new(reqwest::Client::builder().build().expect("test client"));
        let redirect_client = Arc::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("test redirect client"),
        );
        let ctx = ProcessingContext::new(
            NetworkContext::new(
                client,
                redirect_client,
                Arc::new(psl::List),
                Arc::new(
                    TokioResolver::builder_tokio()
                        .unwrap()
                        .with_options(ResolverOpts::default())
                        .build(),
                ),
            ),
            DatabaseContext::new(pool, Arc::new(DbWriteCircuitBreaker::default())),
            ConfigContext::new(
                Arc::new(ProcessingStats::new()),
                Arc::new(TimingStats::new()),
                Some("run-1".to_string()),
                false,
                Arc::new(crate::runtime_metrics::RuntimeMetrics::default()),
            ),
        );
        Arc::new(ctx)
    }

    #[tokio::test]
    async fn test_handle_success_counts_inserted_url_as_successful() {
        let url: Arc<str> = Arc::from("https://example.com");
        let completed_urls = Arc::new(AtomicUsize::new(0));
        let successful_urls = Arc::new(AtomicUsize::new(0));
        let skipped_urls = Arc::new(AtomicUsize::new(0));
        let failed_urls = Arc::new(AtomicUsize::new(0));

        handle_success(
            &url,
            UrlProcessOutcome::Inserted,
            &completed_urls,
            &successful_urls,
            &skipped_urls,
            &failed_urls,
            1,
            &None,
            None,
        )
        .await;

        assert_eq!(completed_urls.load(Ordering::SeqCst), 1);
        assert_eq!(successful_urls.load(Ordering::SeqCst), 1);
        assert_eq!(skipped_urls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_handle_success_counts_skipped_url_separately() {
        let url: Arc<str> = Arc::from("https://example.com");
        let completed_urls = Arc::new(AtomicUsize::new(0));
        let successful_urls = Arc::new(AtomicUsize::new(0));
        let skipped_urls = Arc::new(AtomicUsize::new(0));
        let failed_urls = Arc::new(AtomicUsize::new(0));

        handle_success(
            &url,
            UrlProcessOutcome::Skipped,
            &completed_urls,
            &successful_urls,
            &skipped_urls,
            &failed_urls,
            1,
            &None,
            None,
        )
        .await;

        assert_eq!(completed_urls.load(Ordering::SeqCst), 1);
        assert_eq!(successful_urls.load(Ordering::SeqCst), 0);
        assert_eq!(skipped_urls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_handle_failure_increments_failed_urls_and_invokes_callback() {
        let url: Arc<str> = Arc::from("https://example.com/fail");
        let completed_urls = Arc::new(AtomicUsize::new(0));
        let failed_urls = Arc::new(AtomicUsize::new(0));
        let ctx = minimal_ctx_with_migrations().await;
        let progress_calls = Arc::new(AtomicUsize::new(0));
        let callback: ProgressCallback = Some(Arc::new({
            let progress_calls = Arc::clone(&progress_calls);
            move |completed, failed, _total| {
                progress_calls.store(completed + failed, Ordering::SeqCst);
            }
        }));

        let err = anyhow::anyhow!("simulated failure");
        handle_failure(
            &url,
            err,
            0,
            std::time::Instant::now(),
            &ctx,
            &completed_urls,
            &failed_urls,
            1,
            &callback,
            None,
        )
        .await;

        assert_eq!(failed_urls.load(Ordering::SeqCst), 1);
        assert_eq!(progress_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_handle_failure_with_429_error_completes_without_panic() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(429))
            .mount(&server)
            .await;

        let resp = reqwest::get(server.uri()).await.unwrap();
        let err = resp.error_for_status().unwrap_err();
        let anyhow_err = anyhow::anyhow!(err);

        let url: Arc<str> = Arc::from(server.uri().as_str());
        let completed_urls = Arc::new(AtomicUsize::new(0));
        let failed_urls = Arc::new(AtomicUsize::new(0));
        let ctx = minimal_ctx_with_migrations().await;
        let adaptive = Arc::new(AdaptiveRateLimiter::new(
            10,
            None,
            None,
            Some(0.2),
            None,
            None,
        ));

        handle_failure(
            &url,
            anyhow_err,
            1,
            std::time::Instant::now(),
            &ctx,
            &completed_urls,
            &failed_urls,
            1,
            &None,
            Some(&adaptive),
        )
        .await;

        assert_eq!(failed_urls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_handle_failure_with_non_429_error_does_not_panic() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let resp = reqwest::get(server.uri()).await.unwrap();
        let err = resp.error_for_status().unwrap_err();
        let anyhow_err = anyhow::anyhow!(err);

        let url: Arc<str> = Arc::from(server.uri().as_str());
        let completed_urls = Arc::new(AtomicUsize::new(0));
        let failed_urls = Arc::new(AtomicUsize::new(0));
        let ctx = minimal_ctx_with_migrations().await;
        let adaptive = Arc::new(AdaptiveRateLimiter::new(
            10,
            None,
            None,
            Some(0.2),
            None,
            None,
        ));

        handle_failure(
            &url,
            anyhow_err,
            0,
            std::time::Instant::now(),
            &ctx,
            &completed_urls,
            &failed_urls,
            1,
            &None,
            Some(&adaptive),
        )
        .await;

        assert_eq!(failed_urls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_handle_timeout_increments_failed_urls_and_error_stats() {
        let url: Arc<str> = Arc::from("https://example.com/timeout");
        let completed_urls = Arc::new(AtomicUsize::new(0));
        let failed_urls = Arc::new(AtomicUsize::new(0));
        let ctx = minimal_ctx_with_migrations().await;
        let progress_calls = Arc::new(AtomicUsize::new(0));
        let callback: ProgressCallback = Some(Arc::new({
            let progress_calls = Arc::clone(&progress_calls);
            move |completed, failed, _total| {
                progress_calls.store(completed + failed, Ordering::SeqCst);
            }
        }));
        let adaptive = Arc::new(AdaptiveRateLimiter::new(
            10,
            None,
            None,
            Some(0.2),
            None,
            None,
        ));

        handle_timeout(
            &url,
            std::time::Instant::now(),
            &ctx,
            &completed_urls,
            &failed_urls,
            1,
            &callback,
            Some(&adaptive),
        )
        .await;

        assert_eq!(failed_urls.load(Ordering::SeqCst), 1);
        assert_eq!(progress_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            ctx.config
                .error_stats
                .get_error_count(crate::error_handling::ErrorType::ProcessUrlTimeout),
            1
        );
    }

    #[tokio::test]
    async fn test_handle_failure_when_record_url_failure_fails_does_not_panic() {
        let url: Arc<str> = Arc::from("https://example.com/record-fail");
        let completed_urls = Arc::new(AtomicUsize::new(0));
        let failed_urls = Arc::new(AtomicUsize::new(0));
        let ctx = minimal_ctx_without_migrations().await;
        let progress_calls = Arc::new(AtomicUsize::new(0));
        let callback: ProgressCallback = Some(Arc::new({
            let progress_calls = Arc::clone(&progress_calls);
            move |_completed, failed, _total| {
                progress_calls.store(failed, Ordering::SeqCst);
            }
        }));

        let err = anyhow::anyhow!("simulated failure");
        handle_failure(
            &url,
            err,
            0,
            std::time::Instant::now(),
            &ctx,
            &completed_urls,
            &failed_urls,
            1,
            &callback,
            None,
        )
        .await;

        assert_eq!(failed_urls.load(Ordering::SeqCst), 1);
        assert_eq!(progress_calls.load(Ordering::SeqCst), 1);
    }
}
