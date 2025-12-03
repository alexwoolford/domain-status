//! Main application entry point.
//!
//! Orchestrates URL processing, logging, initialization, and graceful shutdown.
//! This module coordinates the main event loop, task spawning, and resource management.

use anyhow::{Context, Result};
use chrono::Utc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use clap::Parser;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use log::info;
use log::warn;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_util::sync::CancellationToken;

use config::*;
use database::*;
use initialization::*;
use utils::*;

use crate::error_handling::{ErrorType, ProcessingStats};
use crate::fetch::ProcessingContext;
use crate::storage::{record_url_failure, start_batch_writer, BatchConfig};
use crate::utils::ProcessUrlResult;

mod adaptive_rate_limiter;
mod app;
mod config;
mod database;
mod dns;
mod domain;
mod error_handling;
mod fetch;
mod fingerprint;
mod geoip;
mod initialization;
mod models;
mod parse;
mod security;
mod status_server;
mod storage;
mod tls;
mod user_agent;
mod utils;
mod whois;

use app::{
    log_progress, print_and_save_final_statistics, print_timing_statistics, shutdown_gracefully,
    validate_and_normalize_url,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables from .env file (if it exists)
    // This allows setting MAXMIND_LICENSE_KEY in .env without exporting it manually
    // Try loading from current directory first, then from the executable's directory
    if dotenvy::dotenv().is_err() {
        // If .env not found in current dir, try next to the executable
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let env_path = exe_dir.join(".env");
                if env_path.exists() {
                    let _ = dotenvy::from_path(&env_path);
                }
            }
        }
    }

    let mut opt = Opt::parse();

    // Auto-update User-Agent if user didn't override it
    // This ensures the User-Agent stays current over time
    // Check if user provided --user-agent by comparing to default
    if opt.user_agent == crate::config::DEFAULT_USER_AGENT {
        let updated_ua = crate::user_agent::get_default_user_agent(None).await;
        opt.user_agent = updated_ua;
        log::debug!("Using auto-updated User-Agent: {}", opt.user_agent);
    }
    let log_level = opt.log_level.clone();
    let log_format = opt.log_format.clone();
    init_logger_with(log_level.into(), log_format).context("Failed to initialize logger")?;
    init_crypto_provider();

    // Count total lines in file for accurate progress tracking
    let total_lines = {
        let file_for_counting = tokio::fs::File::open(&opt.file)
            .await
            .context("Failed to open input file for line counting")?;
        let reader = BufReader::new(file_for_counting);
        let mut count = 0usize;
        let mut lines = reader.lines();
        while let Ok(Some(_)) = lines.next_line().await {
            count += 1;
        }
        count
    };
    info!("Total URLs in file: {}", total_lines);

    let file = tokio::fs::File::open(&opt.file)
        .await
        .context("Failed to open input file")?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let mut tasks = FuturesUnordered::new();

    let semaphore = init_semaphore(opt.max_concurrency);
    // Calculate burst capacity: cap at min(concurrency, rps * 2) to prevent excessive queuing
    // This ensures rate limiting and concurrency work together, not independently
    let rate_burst = if opt.rate_limit_rps > 0 {
        // Cap burst at 2x RPS or concurrency, whichever is smaller
        std::cmp::min(opt.max_concurrency, (opt.rate_limit_rps * 2) as usize)
    } else {
        // If rate limiting disabled, use concurrency as burst
        opt.max_concurrency
    };
    let (request_limiter, rate_limiter_shutdown) =
        match init_rate_limiter(opt.rate_limit_rps, rate_burst) {
            Some((limiter, shutdown)) => (Some(limiter), Some(shutdown)),
            None => (None, None),
        };

    // Initialize adaptive rate limiter (always enabled when rate limiting is on)
    let adaptive_limiter = if opt.rate_limit_rps > 0 {
        use adaptive_rate_limiter::AdaptiveRateLimiter;
        let adaptive = Arc::new(AdaptiveRateLimiter::new(
            opt.rate_limit_rps,
            Some(1),                      // min RPS
            Some(opt.rate_limit_rps * 2), // max RPS: 2x initial (allows system to adapt to good conditions)
            Some(opt.adaptive_error_threshold),
            None, // default window size (100)
            None, // default window duration (30s)
        ));

        // Start adaptive adjustment task
        if let Some(ref rate_limiter) = request_limiter {
            let rate_limiter_clone = Arc::clone(rate_limiter);
            let _shutdown_token = adaptive.start_adaptive_adjustment(
                move |new_rps| {
                    rate_limiter_clone.update_rps(new_rps);
                },
                None, // default adjustment interval (5s)
            );
            // Shutdown token is dropped here - the task will run until main exits
        }

        Some(adaptive)
    } else {
        None
    };

    // Override DB path env for init if needed
    std::env::set_var(
        "URL_CHECKER_DB_PATH",
        opt.db_path.to_string_lossy().to_string(),
    );

    let pool = init_db_pool()
        .await
        .context("Failed to initialize database pool")?;
    let client = init_client(&opt)
        .await
        .context("Failed to initialize HTTP client")?;
    let redirect_client = init_redirect_client(&opt)
        .await
        .context("Failed to initialize redirect client")?;
    let extractor = init_extractor();
    let resolver = init_resolver().context("Failed to initialize DNS resolver")?;

    run_migrations(&pool)
        .await
        .context("Failed to run database migrations")?;

    // Initialize technology fingerprint ruleset
    // Log WHOIS status
    if opt.enable_whois {
        info!("WHOIS/RDAP lookup enabled (rate limit: 1 query per 2 seconds)");
    }

    let ruleset = fingerprint::init_ruleset(opt.fingerprints.as_deref(), None)
        .await
        .context("Failed to initialize fingerprint ruleset")?;

    // Initialize GeoIP database (optional)
    // If initialization fails, we continue without GeoIP rather than aborting
    let geoip_metadata = match geoip::init_geoip(opt.geoip.as_deref(), None).await {
        Ok(metadata) => metadata,
        Err(e) => {
            warn!(
                "Failed to initialize GeoIP database: {}. Continuing without GeoIP lookup.",
                e
            );
            warn!("To enable GeoIP, ensure MAXMIND_LICENSE_KEY in .env is valid and your MaxMind account has GeoLite2 access.");
            None
        }
    };

    // Generate run_id and start_time for time-series tracking
    // Format: run_<timestamp_millis> for human-readable, sortable IDs
    let start_time_epoch = Utc::now().timestamp_millis();
    let run_id = format!("run_{}", start_time_epoch);
    info!("Starting run: {}", run_id);

    // Store run metadata (fingerprints_source, fingerprints_version, and geoip_version are run-level, not per-URL)
    let fingerprints_source = Some(ruleset.metadata.source.as_str());
    let fingerprints_version = Some(ruleset.metadata.version.as_str());
    let geoip_version = geoip_metadata.as_ref().map(|m| m.version.as_str());
    database::insert_run_metadata(
        &pool,
        &run_id,
        start_time_epoch,
        fingerprints_source,
        fingerprints_version,
        geoip_version,
    )
    .await
    .context("Failed to insert run metadata")?;

    // Start batch writer for efficient database writes
    let batch_config = BatchConfig {
        batch_size: BATCH_SIZE,
        flush_interval_secs: BATCH_FLUSH_INTERVAL_SECS,
    };
    // Initialize batch write counters for status server
    let batch_write_successes = Arc::new(AtomicUsize::new(0));
    let batch_write_failures = Arc::new(AtomicUsize::new(0));

    // Clone the pool for the batch writer (Arc<SqlitePool> -> SqlitePool via deref)
    let pool_for_batch = (*pool).clone();
    let (batch_sender, batch_writer_handle) = start_batch_writer(
        pool_for_batch,
        batch_config,
        Some(Arc::clone(&batch_write_successes)),
        Some(Arc::clone(&batch_write_failures)),
    );
    info!(
        "Batch writer started (batch_size={}, flush_interval={}s)",
        BATCH_SIZE, BATCH_FLUSH_INTERVAL_SECS
    );

    // Start time for measuring elapsed time during processing
    let start_time = std::time::Instant::now();
    let start_time_arc = Arc::new(start_time);

    let error_stats = Arc::new(ProcessingStats::new());

    // Initialize circuit breaker for database write failures
    let db_circuit_breaker =
        Arc::new(crate::storage::circuit_breaker::DbWriteCircuitBreaker::new());
    info!("Database write circuit breaker initialized (threshold: 5 failures, cooldown: 60s)");

    // Initialize timing statistics tracker
    let timing_stats = Arc::new(crate::utils::TimingStats::new());

    let completed_urls = Arc::new(AtomicUsize::new(0));
    let failed_urls = Arc::new(AtomicUsize::new(0));
    let total_urls_attempted = Arc::new(AtomicUsize::new(0));
    let total_urls_in_file = Arc::new(AtomicUsize::new(total_lines));

    // Start status server if requested
    if let Some(port) = opt.status_port {
        let status_state = status_server::StatusState {
            total_urls: Arc::clone(&total_urls_in_file), // Use total lines in file, not URLs attempted so far
            completed_urls: Arc::clone(&completed_urls),
            failed_urls: Arc::clone(&failed_urls),
            start_time: Arc::clone(&start_time_arc),
            error_stats: error_stats.clone(),
            batch_write_successes: Arc::clone(&batch_write_successes),
            batch_write_failures: Arc::clone(&batch_write_failures),
        };
        tokio::spawn(async move {
            if let Err(e) = status_server::start_status_server(port, status_state).await {
                log::warn!("Status server error: {}", e);
            }
        });
    }

    // Create shared processing context once (reused for all tasks)
    // This avoids creating a new context for each URL, simplifying the hot path
    let shared_ctx = Arc::new(ProcessingContext::new(
        Arc::clone(&client),
        Arc::clone(&redirect_client),
        Arc::clone(&extractor),
        Arc::clone(&resolver),
        error_stats.clone(),
        Some(run_id.clone()),
        Some(batch_sender.clone()),
        opt.enable_whois,
        Arc::clone(&db_circuit_breaker),
        Arc::clone(&pool),
        Arc::clone(&timing_stats),
    ));

    loop {
        let line_result = lines.next_line().await;
        let line = match line_result {
            Ok(Some(line)) => line,
            Ok(None) => break, // EOF reached
            Err(e) => {
                warn!("Failed to read line from input file: {e}");
                continue;
            }
        };

        // Validate and normalize URL: only allow http/https and syntactically valid
        let Some(url) = validate_and_normalize_url(&line) else {
            continue;
        };

        // Increment total URLs counter for every URL that passes validation
        total_urls_attempted.fetch_add(1, Ordering::SeqCst);

        let permit = match Arc::clone(&semaphore).acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => {
                warn!("Semaphore closed, skipping URL: {url}");
                continue;
            }
        };

        // Clone shared context (cheap - just Arc pointer increment)
        // Context is created once before the loop and reused for all tasks
        let ctx = Arc::clone(&shared_ctx);

        // Clone counters for use in the task
        let completed_urls_clone = Arc::clone(&completed_urls);
        let failed_urls_clone = Arc::clone(&failed_urls);

        // Share URL using Arc<str> to avoid multiple clones
        // Arc<str> can be dereferenced to &str for logging and error messages
        let url_shared = Arc::from(url.as_str());

        let request_limiter_clone = request_limiter.as_ref().map(Arc::clone);
        let adaptive_limiter_for_task = adaptive_limiter.as_ref().map(Arc::clone);
        tasks.push(tokio::spawn(async move {
            let _permit = permit;

            if let Some(ref limiter) = request_limiter_clone {
                limiter.acquire().await;
            }

            let process_start = std::time::Instant::now();

            // Use shared URL for logging (Arc<str> can be dereferenced to &str)
            let url_for_logging = Arc::clone(&url_shared);

            let result =
                tokio::time::timeout(URL_PROCESSING_TIMEOUT, process_url(url_shared, ctx.clone()))
                    .await;

            match result {
                Ok(ProcessUrlResult { result: Ok(()), .. }) => {
                    completed_urls_clone.fetch_add(1, Ordering::SeqCst);
                    if let Some(adaptive) = adaptive_limiter_for_task {
                        adaptive.record_success().await;
                    }
                }
                Ok(ProcessUrlResult {
                    result: Err(e),
                    retry_count,
                }) => {
                    // Increment failed URLs counter
                    failed_urls_clone.fetch_add(1, Ordering::SeqCst);

                    log::warn!("Failed to process URL {}: {e}", url_for_logging.as_ref());

                    // Record failure in database with accurate retry count
                    let elapsed = process_start.elapsed().as_secs_f64();
                    // Extract context from error (uses structured context if available, falls back to string parsing)
                    let context = crate::storage::failure::extract_failure_context(&e);
                    if let Err(record_err) = record_url_failure(
                        &ctx.pool,
                        &ctx.extractor,
                        url_for_logging.as_ref(),
                        &e,
                        context,
                        retry_count, // Use actual retry count from process_url
                        elapsed,
                        ctx.run_id.as_deref(),
                        Arc::clone(&ctx.db_circuit_breaker),
                    )
                    .await
                    {
                        log::warn!(
                            "Failed to record failure for {}: {}",
                            url_for_logging.as_ref(),
                            record_err
                        );
                    }

                    // Note: Error stats are already updated in handle_http_request via update_error_stats
                    // No need to duplicate here - this was causing double counting
                    // Only handle adaptive limiter for rate limiting
                    if let Some(adaptive) = adaptive_limiter_for_task {
                        let is_429 = e.chain().any(|cause| {
                            if let Some(reqwest_err) = cause.downcast_ref::<reqwest::Error>() {
                                reqwest_err
                                    .status()
                                    .map(|s| {
                                        s.as_u16() == crate::config::HTTP_STATUS_TOO_MANY_REQUESTS
                                    })
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
                Err(_) => {
                    // Increment failed URLs counter for timeout
                    failed_urls_clone.fetch_add(1, Ordering::SeqCst);

                    log::warn!("Timeout processing URL {}", url_for_logging.as_ref());

                    // Record timeout failure in database
                    // For timeout at process_url level, we don't have the inner error context
                    // (the timeout occurred before process_url completed)
                    // But we can still record the timeout with the URL context
                    let elapsed = process_start.elapsed().as_secs_f64();
                    let timeout_error = anyhow::anyhow!(
                        "Process URL timeout after {} seconds for {}",
                        URL_PROCESSING_TIMEOUT.as_secs(),
                        url_for_logging.as_ref()
                    );

                    // Create minimal context (no response/redirect info available for timeout)
                    let context = crate::storage::failure::FailureContext {
                        final_url: None,
                        redirect_chain: Vec::new(),
                        response_headers: Vec::new(),
                        request_headers: Vec::new(),
                    };
                    if let Err(record_err) = record_url_failure(
                        &ctx.pool,
                        &ctx.extractor,
                        url_for_logging.as_ref(),
                        &timeout_error,
                        context,
                        crate::config::RETRY_MAX_ATTEMPTS as u32 - 1, // Max retries attempted
                        elapsed,
                        ctx.run_id.as_deref(),
                        Arc::clone(&ctx.db_circuit_breaker),
                    )
                    .await
                    {
                        log::warn!(
                            "Failed to record timeout failure for {}: {}",
                            url_for_logging.as_ref(),
                            record_err
                        );
                    }

                    ctx.error_stats
                        .increment_error(ErrorType::ProcessUrlTimeout);
                    if let Some(adaptive) = adaptive_limiter_for_task {
                        adaptive.record_timeout().await;
                    }
                }
            }
        }));
    }

    // Cancellation token for graceful shutdown of periodic logging
    let cancel = CancellationToken::new();
    let cancel_logging = cancel.child_token();

    // Clone the Arc before the logging task
    let completed_urls_clone_for_logging = Arc::clone(&completed_urls);

    // Only log progress if status server is not enabled (to reduce verbosity)
    let logging_task = if opt.status_port.is_none() {
        Some(tokio::task::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(LOGGING_INTERVAL as u64));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        log_progress(start_time, &completed_urls_clone_for_logging);
                    }
                    _ = cancel_logging.cancelled() => {
                        break;
                    }
                }
            }
        }))
    } else {
        // If status server is enabled, log progress less frequently (every 30 seconds)
        // to reduce verbosity while still providing occasional updates
        Some(tokio::task::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                crate::config::STATUS_SERVER_LOGGING_INTERVAL_SECS,
            ));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        log_progress(start_time, &completed_urls_clone_for_logging);
                    }
                    _ = cancel_logging.cancelled() => {
                        break;
                    }
                }
            }
        }))
    };

    // Wait for all tasks to complete
    while (tasks.next().await).is_some() {}

    // Shutdown gracefully
    shutdown_gracefully(
        cancel,
        logging_task,
        rate_limiter_shutdown,
        batch_sender,
        batch_writer_handle,
    )
    .await;

    // Log one final time before printing the error summary
    log_progress(start_time, &completed_urls);

    // Print final statistics and update database
    print_and_save_final_statistics(
        &pool,
        &run_id,
        &total_urls_attempted,
        &completed_urls,
        &error_stats,
    )
    .await
    .context("Failed to save final statistics")?;

    // Print timing statistics if enabled
    if opt.show_timing {
        print_timing_statistics(&timing_stats);
    }

    Ok(())
}
