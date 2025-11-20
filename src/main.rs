// main.rs
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
use regex::Regex;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_util::sync::CancellationToken;

use config::*;
use database::*;
use initialization::*;
use strum::IntoEnumIterator;
use utils::*;

use crate::error_handling::{ErrorType, InfoType, ProcessingStats, WarningType};
use crate::fetch::ProcessingContext;
use crate::storage::{start_batch_writer, BatchConfig};

mod adaptive_rate_limiter;
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
mod storage;
mod tls;
mod utils;

/// Logs progress information about URL processing.
///
/// # Arguments
///
/// * `start_time` - The start time of processing
/// * `completed_urls` - Atomic counter of completed URLs
fn log_progress(start_time: std::time::Instant, completed_urls: &Arc<AtomicUsize>) {
    let elapsed = start_time.elapsed();
    let completed = completed_urls.load(Ordering::SeqCst);
    let elapsed_secs = elapsed.as_secs_f64();
    let rate = if elapsed_secs > 0.0 {
        completed as f64 / elapsed_secs
    } else {
        0.0
    };
    info!(
        "Processed {} lines in {:.2} seconds (~{:.2} lines/sec)",
        completed, elapsed_secs, rate
    );
}

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

    let opt = Opt::parse();
    let log_level = opt.log_level.clone();
    let log_format = opt.log_format.clone();
    init_logger_with(log_level.into(), log_format).context("Failed to initialize logger")?;
    init_crypto_provider();

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
            Some(1),                  // min RPS
            Some(opt.rate_limit_rps), // max RPS (initial value)
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
    // Clone the pool for the batch writer (Arc<SqlitePool> -> SqlitePool via deref)
    let pool_for_batch = (*pool).clone();
    let (batch_sender, batch_writer_handle) = start_batch_writer(pool_for_batch, batch_config);
    info!(
        "Batch writer started (batch_size={}, flush_interval={}s)",
        BATCH_SIZE, BATCH_FLUSH_INTERVAL_SECS
    );

    // Start time for measuring elapsed time during processing
    let start_time = std::time::Instant::now();

    let error_stats = Arc::new(ProcessingStats::new());

    let completed_urls = Arc::new(AtomicUsize::new(0));
    let total_urls_attempted = Arc::new(AtomicUsize::new(0));

    let url_regex = Regex::new(crate::config::URL_SCHEME_PATTERN)
        .map_err(|e| anyhow::anyhow!("Failed to compile URL regex pattern: {}", e))?;

    loop {
        let line_result = lines.next_line().await;
        let url = match line_result {
            Ok(Some(line)) => {
                if !url_regex.is_match(&line) {
                    format!("https://{line}")
                } else {
                    line
                }
            }
            Ok(None) => break, // EOF reached
            Err(e) => {
                warn!("Failed to read line from input file: {e}");
                continue;
            }
        };

        // Validate URL: only allow http/https and syntactically valid
        match url::Url::parse(&url) {
            Ok(parsed) => match parsed.scheme() {
                "http" | "https" => {}
                _ => {
                    warn!("Skipping unsupported scheme for URL: {url}");
                    continue;
                }
            },
            Err(_) => {
                warn!("Skipping invalid URL: {url}");
                continue;
            }
        }

        // Increment total URLs counter for every URL that passes validation
        total_urls_attempted.fetch_add(1, Ordering::SeqCst);

        let permit = match Arc::clone(&semaphore).acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => {
                warn!("Semaphore closed, skipping URL: {url}");
                continue;
            }
        };

        // Create processing context for this task
        let ctx = Arc::new(ProcessingContext::new(
            Arc::clone(&client),
            Arc::clone(&redirect_client),
            Arc::clone(&pool),
            Arc::clone(&extractor),
            Arc::clone(&resolver),
            error_stats.clone(),
            Some(run_id.clone()),
            Some(batch_sender.clone()),
        ));

        // Clone error_stats for use in the task (it's also in ctx, but we need it here for error reporting)
        let error_stats_clone = error_stats.clone();
        let completed_urls_clone = Arc::clone(&completed_urls);

        // Wrap URL in Arc to avoid cloning on retries
        let url_arc = Arc::new(url);

        let request_limiter_clone = request_limiter.as_ref().map(Arc::clone);
        let adaptive_limiter_for_task = adaptive_limiter.as_ref().map(Arc::clone);
        tasks.push(tokio::spawn(async move {
            let _permit = permit;

            if let Some(ref limiter) = request_limiter_clone {
                limiter.acquire().await;
            }

            // Clone Arc for error messages (cheap - just pointer increment)
            let url_for_logging = Arc::clone(&url_arc);

            let result =
                tokio::time::timeout(URL_PROCESSING_TIMEOUT, process_url(url_arc, ctx)).await;

            match result {
                Ok(Ok(())) => {
                    completed_urls_clone.fetch_add(1, Ordering::SeqCst);
                    if let Some(adaptive) = adaptive_limiter_for_task {
                        adaptive.record_success().await;
                    }
                }
                Ok(Err(e)) => {
                    log::warn!("Failed to process URL {url_for_logging}: {e}");
                    // Check if this is a 429 error
                    let is_429 = e.chain().any(|cause| {
                        if let Some(reqwest_err) = cause.downcast_ref::<reqwest::Error>() {
                            reqwest_err.status() == Some(reqwest::StatusCode::TOO_MANY_REQUESTS)
                        } else {
                            false
                        }
                    });

                    if is_429 {
                        error_stats_clone.increment_error(ErrorType::HttpRequestTooManyRequests);
                        if let Some(adaptive) = adaptive_limiter_for_task {
                            adaptive.record_rate_limited().await;
                        }
                    } else {
                        error_stats_clone.increment_error(ErrorType::HttpRequestOtherError);
                    }
                }
                Err(_) => {
                    log::warn!("Timeout processing URL {url_for_logging}");
                    error_stats_clone.increment_error(ErrorType::ProcessUrlTimeout);
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

    let logging_task = tokio::task::spawn(async move {
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
    });

    // Wait for all tasks to complete
    while (tasks.next().await).is_some() {}

    // Signal logging task to stop and await it
    cancel.cancel();
    let _ = logging_task.await;

    // Signal rate limiter to stop if it exists
    if let Some(shutdown) = rate_limiter_shutdown {
        shutdown.cancel();
    }

    // Flush batch writer: close the channel and wait for remaining records to be written
    info!("Flushing batch writer...");
    drop(batch_sender); // Close the channel to signal shutdown
    match batch_writer_handle.await {
        Ok(Ok(())) => info!("Batch writer flushed successfully"),
        Ok(Err(e)) => warn!("Error flushing batch writer: {}", e),
        Err(e) => warn!("Batch writer task panicked: {}", e),
    }

    // Log one final time before printing the error summary
    log_progress(start_time, &completed_urls);

    // Calculate run statistics
    // All tasks have completed at this point, so counters should be final
    let total_urls = total_urls_attempted.load(Ordering::SeqCst) as i32;
    let successful_urls = completed_urls.load(Ordering::SeqCst) as i32;
    let failed_urls = total_urls - successful_urls;

    info!(
        "Run statistics: total={}, successful={}, failed={}",
        total_urls, successful_urls, failed_urls
    );

    // Update run statistics in database
    database::update_run_stats(&pool, &run_id, total_urls, successful_urls, failed_urls)
        .await
        .context("Failed to update run statistics")?;

    // Print processing statistics
    let total_errors = error_stats.total_errors();
    let total_warnings = error_stats.total_warnings();
    let total_info = error_stats.total_info();

    if total_errors > 0 {
        info!("Error Counts ({} total):", total_errors);
        for error_type in ErrorType::iter() {
            let count = error_stats.get_error_count(error_type);
            if count > 0 {
                info!("   {}: {}", error_type.as_str(), count);
            }
        }
    }

    if total_warnings > 0 {
        info!("Warning Counts ({} total):", total_warnings);
        for warning_type in WarningType::iter() {
            let count = error_stats.get_warning_count(warning_type);
            if count > 0 {
                info!("   {}: {}", warning_type.as_str(), count);
            }
        }
    }

    if total_info > 0 {
        info!("Info Counts ({} total):", total_info);
        for info_type in InfoType::iter() {
            let count = error_stats.get_info_count(info_type);
            if count > 0 {
                info!("   {}: {}", info_type.as_str(), count);
            }
        }
    }

    Ok(())
}
