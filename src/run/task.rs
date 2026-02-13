//! Per-URL task processing.
//!
//! This module contains the logic for processing a single URL, including
//! success/failure/timeout handling.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::config::{HTTP_STATUS_TOO_MANY_REQUESTS, RETRY_MAX_ATTEMPTS, URL_PROCESSING_TIMEOUT};
use crate::error_handling::ErrorType;
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
        completed_urls,
        failed_urls,
        total_urls_for_callback,
        progress_callback,
    } = params;

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
        Ok(ProcessUrlResult { result: Ok(()), .. }) => {
            handle_success(
                &completed_urls,
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
async fn handle_success(
    completed_urls: &Arc<std::sync::atomic::AtomicUsize>,
    failed_urls: &Arc<std::sync::atomic::AtomicUsize>,
    total_urls_for_callback: usize,
    progress_callback: &ProgressCallback,
    adaptive_limiter: Option<&Arc<crate::adaptive_rate_limiter::AdaptiveRateLimiter>>,
) {
    completed_urls.fetch_add(1, Ordering::SeqCst);
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
    invoke_progress_callback(
        progress_callback,
        completed_urls,
        failed_urls,
        total_urls_for_callback,
    );
    log::warn!("Failed to process URL {}: {error}", url.as_ref());

    let elapsed = process_start.elapsed().as_secs_f64();
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

    let elapsed = process_start.elapsed().as_secs_f64();
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
