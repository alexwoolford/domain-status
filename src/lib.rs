//! domain_status library: core URL scanning functionality
//!
//! This library provides high-level APIs for scanning URLs and capturing comprehensive
//! metadata including HTTP status, TLS certificates, DNS information, technology
//! fingerprints, and more.
//!
//! # Example
//!
//! ```no_run
//! use domain_status::{Config, run_scan};
//! use tokio;
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = Config {
//!     file: std::path::PathBuf::from("urls.txt"),
//!     max_concurrency: 50,
//!     rate_limit_rps: 20,
//!     ..Default::default()
//! };
//!
//! let report = run_scan(config).await?;
//! println!("Processed {} URLs: {} succeeded, {} failed",
//!          report.total_urls, report.successful, report.failed);
//! # Ok(())
//! # }
//! ```
//!
//! # Requirements
//!
//! This library requires a Tokio runtime. Use `#[tokio::main]` in your application
//! or ensure you're calling library functions within an async context.

#![warn(missing_docs)]

mod adaptive_rate_limiter;
mod app;
pub mod config;
mod database;
mod dns;
mod domain;
mod error_handling;
pub mod export;
mod fetch;
mod fingerprint;
mod geoip;
pub mod initialization;
mod models;
mod parse;
mod security;
mod status_server;
mod storage;
mod tls;
mod user_agent;
mod utils;
mod whois;

// Re-export public API
pub use config::{Config, FailOn, LogFormat, LogLevel};
pub use run::{run_scan, ScanReport};
pub use storage::{query_run_history, run_migrations, RunSummary};

// Internal run module (contains the main scanning logic)
mod run {
    use anyhow::{Context, Result};
    use chrono::Utc;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use futures::stream::FuturesUnordered;
    use futures::StreamExt;
    use log::{info, warn};
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio_util::sync::CancellationToken;

    use crate::adaptive_rate_limiter::AdaptiveRateLimiter;
    use crate::app::statistics::print_error_statistics;
    use crate::app::{
        log_progress, print_timing_statistics, shutdown_gracefully, validate_and_normalize_url,
    };
    use crate::config::{Config, DEFAULT_USER_AGENT};
    use crate::config::{
        LOGGING_INTERVAL, RETRY_MAX_ATTEMPTS, STATUS_SERVER_LOGGING_INTERVAL_SECS,
        URL_PROCESSING_TIMEOUT,
    };
    use crate::error_handling::{ErrorType, ProcessingStats};
    use crate::fetch::ProcessingContext;
    use crate::initialization::*;
    use crate::storage::init_db_pool_with_path;
    use crate::storage::{insert_run_metadata, record_url_failure, update_run_stats};
    use crate::utils::{ProcessUrlResult, TimingStats};

    /// Results of a URL scanning run.
    ///
    /// Contains summary statistics and metadata about the completed scan.
    #[derive(Debug, Clone)]
    pub struct ScanReport {
        /// Total number of URLs processed
        pub total_urls: usize,
        /// Number of URLs successfully processed
        pub successful: usize,
        /// Number of URLs that failed to process
        pub failed: usize,
        /// Path to the SQLite database containing results
        pub db_path: PathBuf,
        /// Run identifier (format: `run_<timestamp_millis>`)
        pub run_id: String,
        /// Elapsed time in seconds
        pub elapsed_seconds: f64,
    }

    /// Runs a URL scan with the provided configuration.
    ///
    /// This is the main entry point for the library. It reads URLs from the input file,
    /// processes them concurrently, and stores results in a SQLite database.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration for the scan (file path, concurrency, timeouts, etc.)
    ///
    /// # Returns
    ///
    /// Returns a `ScanReport` containing summary statistics, or an error if the scan
    /// failed to complete.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The input file cannot be opened
    /// - Database initialization fails
    /// - Network resources cannot be initialized
    ///
    /// # Example
    ///
    /// ```no_run
    /// use domain_status::{Config, run_scan};
    /// use std::path::PathBuf;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = Config {
    ///     file: PathBuf::from("urls.txt"),
    ///     ..Default::default()
    /// };
    /// let report = run_scan(config).await?;
    /// println!("Processed {} URLs", report.total_urls);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn run_scan(mut config: Config) -> Result<ScanReport> {
        if config.user_agent == DEFAULT_USER_AGENT {
            let updated_ua = crate::user_agent::get_default_user_agent(None).await;
            config.user_agent = updated_ua;
            log::debug!("Using auto-updated User-Agent: {}", config.user_agent);
        }

        let (total_lines, is_stdin) = if config.file.as_os_str() == "-" {
            info!("Reading URLs from stdin");
            (0, true)
        } else {
            let file_for_counting = tokio::fs::File::open(&config.file)
                .await
                .context("Failed to open input file for line counting")?;
            let reader = BufReader::new(file_for_counting);
            let mut count = 0usize;
            let mut counting_lines = reader.lines();
            while let Ok(Some(line)) = counting_lines.next_line().await {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    count += 1;
                }
            }
            info!("Total URLs in file: {}", count);
            (count, false)
        };

        let mut stdin_lines = if is_stdin {
            use tokio::io::stdin;
            Some(BufReader::new(stdin()).lines())
        } else {
            None
        };

        let mut file_lines = if !is_stdin {
            let file = tokio::fs::File::open(&config.file)
                .await
                .context("Failed to open input file")?;
            Some(BufReader::new(file).lines())
        } else {
            None
        };

        let mut tasks = FuturesUnordered::new();

        let semaphore = init_semaphore(config.max_concurrency);
        let rate_burst = if config.rate_limit_rps > 0 {
            let rps_doubled = config.rate_limit_rps.saturating_mul(2);
            std::cmp::min(config.max_concurrency, rps_doubled as usize)
        } else {
            config.max_concurrency
        };
        let (request_limiter, rate_limiter_shutdown) =
            match init_rate_limiter(config.rate_limit_rps, rate_burst) {
                Some((limiter, shutdown)) => (Some(limiter), Some(shutdown)),
                None => (None, None),
            };

        let adaptive_limiter = if config.rate_limit_rps > 0 {
            let max_rps = config.rate_limit_rps.saturating_mul(2);
            let adaptive = Arc::new(AdaptiveRateLimiter::new(
                config.rate_limit_rps,
                Some(1),
                Some(max_rps),
                Some(config.adaptive_error_threshold),
                None,
                None,
            ));

            if let Some(ref rate_limiter) = request_limiter {
                let rate_limiter_clone = Arc::clone(rate_limiter);
                let _shutdown_token = adaptive.start_adaptive_adjustment(
                    move |new_rps| {
                        rate_limiter_clone.update_rps(new_rps);
                    },
                    None,
                );
            }

            Some(adaptive)
        } else {
            None
        };

        let pool = init_db_pool_with_path(&config.db_path)
            .await
            .context("Failed to initialize database pool")?;
        let client = init_client(&config)
            .await
            .context("Failed to initialize HTTP client")?;
        let redirect_client = init_redirect_client(&config)
            .await
            .context("Failed to initialize redirect client")?;
        let extractor = init_extractor();
        let resolver = init_resolver().context("Failed to initialize DNS resolver")?;

        crate::storage::run_migrations(&pool)
            .await
            .context("Failed to run database migrations")?;

        if config.enable_whois {
            info!("WHOIS/RDAP lookup enabled (rate limit: 1 query per 2 seconds)");
        }

        let ruleset = crate::fingerprint::init_ruleset(config.fingerprints.as_deref(), None)
            .await
            .context("Failed to initialize fingerprint ruleset")?;

        let geoip_metadata = match crate::geoip::init_geoip(config.geoip.as_deref(), None).await {
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

        let start_time_epoch = Utc::now().timestamp_millis();
        let run_id = format!("run_{}", start_time_epoch);
        info!("Starting run: {}", run_id);

        let fingerprints_source = Some(ruleset.metadata.source.as_str());
        let fingerprints_version = Some(ruleset.metadata.version.as_str());
        let geoip_version = geoip_metadata.as_ref().map(|m| m.version.as_str());
        insert_run_metadata(
            &pool,
            &run_id,
            start_time_epoch,
            env!("CARGO_PKG_VERSION"), // Get version from Cargo.toml at compile time
            fingerprints_source,
            fingerprints_version,
            geoip_version,
        )
        .await
        .context("Failed to insert run metadata")?;

        let start_time = std::time::Instant::now();
        let start_time_arc = Arc::new(start_time);

        let error_stats = Arc::new(ProcessingStats::new());

        let db_circuit_breaker =
            Arc::new(crate::storage::circuit_breaker::DbWriteCircuitBreaker::new());
        info!("Database write circuit breaker initialized (threshold: 5 failures, cooldown: 60s)");

        let timing_stats = Arc::new(TimingStats::new());

        let completed_urls = Arc::new(AtomicUsize::new(0));
        let failed_urls = Arc::new(AtomicUsize::new(0));
        let total_urls_attempted = Arc::new(AtomicUsize::new(0));
        let total_urls_in_file = Arc::new(AtomicUsize::new(total_lines));

        if let Some(port) = config.status_port {
            let status_state = crate::status_server::StatusState {
                total_urls: Arc::clone(&total_urls_in_file),
                total_urls_attempted: Arc::clone(&total_urls_attempted),
                completed_urls: Arc::clone(&completed_urls),
                failed_urls: Arc::clone(&failed_urls),
                start_time: Arc::clone(&start_time_arc),
                error_stats: error_stats.clone(),
                timing_stats: Some(Arc::clone(&timing_stats)),
            };
            tokio::spawn(async move {
                if let Err(e) = crate::status_server::start_status_server(port, status_state).await
                {
                    log::warn!("Status server error: {}", e);
                }
            });
        }

        let shared_ctx = Arc::new(ProcessingContext::new(
            Arc::clone(&client),
            Arc::clone(&redirect_client),
            Arc::clone(&extractor),
            Arc::clone(&resolver),
            error_stats.clone(),
            Some(run_id.clone()),
            config.enable_whois,
            Arc::clone(&db_circuit_breaker),
            Arc::clone(&pool),
            Arc::clone(&timing_stats),
        ));

        loop {
            let line_result = if is_stdin {
                stdin_lines
                    .as_mut()
                    .expect("stdin_lines should be Some when is_stdin is true")
                    .next_line()
                    .await
            } else {
                file_lines
                    .as_mut()
                    .expect("file_lines should be Some when is_stdin is false")
                    .next_line()
                    .await
            };
            let line = match line_result {
                Ok(Some(line)) => line,
                Ok(None) => break,
                Err(e) => {
                    warn!("Failed to read line from input: {e}");
                    continue;
                }
            };

            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let Some(url) = validate_and_normalize_url(trimmed) else {
                continue;
            };

            let permit = match Arc::clone(&semaphore).acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => {
                    warn!("Semaphore closed, skipping URL: {url}");
                    continue;
                }
            };

            total_urls_attempted.fetch_add(1, Ordering::SeqCst);

            let ctx = Arc::clone(&shared_ctx);
            let completed_urls_clone = Arc::clone(&completed_urls);
            let failed_urls_clone = Arc::clone(&failed_urls);
            let url_shared = Arc::from(url.as_str());

            let request_limiter_clone = request_limiter.as_ref().map(Arc::clone);
            let adaptive_limiter_for_task = adaptive_limiter.as_ref().map(Arc::clone);
            tasks.push(tokio::spawn(async move {
                let _permit = permit;

                if let Some(ref limiter) = request_limiter_clone {
                    limiter.acquire().await;
                }

                let process_start = std::time::Instant::now();
                let url_for_logging = Arc::clone(&url_shared);

                let result = tokio::time::timeout(
                    URL_PROCESSING_TIMEOUT,
                    crate::utils::process_url(url_shared, ctx.clone()),
                )
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
                        failed_urls_clone.fetch_add(1, Ordering::SeqCst);
                        log::warn!("Failed to process URL {}: {e}", url_for_logging.as_ref());

                        let elapsed = process_start.elapsed().as_secs_f64();
                        let context = crate::storage::failure::extract_failure_context(&e);
                        if let Err(record_err) =
                            record_url_failure(crate::storage::failure::FailureRecordParams {
                                pool: &ctx.db.pool,
                                extractor: &ctx.network.extractor,
                                url: url_for_logging.as_ref(),
                                error: &e,
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
                                url_for_logging.as_ref(),
                                record_err
                            );
                        }

                        if let Some(adaptive) = adaptive_limiter_for_task {
                            let is_429 = e.chain().any(|cause| {
                                if let Some(reqwest_err) = cause.downcast_ref::<reqwest::Error>() {
                                    reqwest_err
                                        .status()
                                        .map(|s| {
                                            s.as_u16()
                                                == crate::config::HTTP_STATUS_TOO_MANY_REQUESTS
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
                        failed_urls_clone.fetch_add(1, Ordering::SeqCst);
                        log::warn!("Timeout processing URL {}", url_for_logging.as_ref());

                        let elapsed = process_start.elapsed().as_secs_f64();
                        let timeout_error = anyhow::anyhow!(
                            "Process URL timeout after {} seconds for {}",
                            URL_PROCESSING_TIMEOUT.as_secs(),
                            url_for_logging.as_ref()
                        );

                        let context = crate::storage::failure::FailureContext {
                            final_url: None,
                            redirect_chain: Vec::new(),
                            response_headers: Vec::new(),
                            request_headers: Vec::new(),
                        };
                        if let Err(record_err) =
                            record_url_failure(crate::storage::failure::FailureRecordParams {
                                pool: &ctx.db.pool,
                                extractor: &ctx.network.extractor,
                                url: url_for_logging.as_ref(),
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
                                url_for_logging.as_ref(),
                                record_err
                            );
                        }

                        ctx.config
                            .error_stats
                            .increment_error(ErrorType::ProcessUrlTimeout);
                        if let Some(adaptive) = adaptive_limiter_for_task {
                            adaptive.record_timeout().await;
                        }
                    }
                }
            }));
        }

        let cancel = CancellationToken::new();
        let cancel_logging = cancel.child_token();

        let completed_urls_clone_for_logging = Arc::clone(&completed_urls);
        let failed_urls_clone_for_logging = Arc::clone(&failed_urls);
        let total_urls_clone_for_logging = Arc::clone(&total_urls_attempted);

        let logging_task = if config.status_port.is_none() {
            Some(tokio::task::spawn(async move {
                let mut interval =
                    tokio::time::interval(std::time::Duration::from_secs(LOGGING_INTERVAL as u64));
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            log_progress(start_time, &completed_urls_clone_for_logging, &failed_urls_clone_for_logging, Some(&total_urls_clone_for_logging));
                        }
                        _ = cancel_logging.cancelled() => {
                            break;
                        }
                    }
                }
            }))
        } else {
            Some(tokio::task::spawn(async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                    STATUS_SERVER_LOGGING_INTERVAL_SECS,
                ));
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                            log_progress(start_time, &completed_urls_clone_for_logging, &failed_urls_clone_for_logging, Some(&total_urls_clone_for_logging));
                        }
                        _ = cancel_logging.cancelled() => {
                            break;
                        }
                    }
                }
            }))
        };

        while let Some(task_result) = tasks.next().await {
            if let Err(join_error) = task_result {
                failed_urls.fetch_add(1, Ordering::SeqCst);
                log::warn!("Task panicked: {:?}", join_error);
            }
        }

        shutdown_gracefully(cancel, logging_task, rate_limiter_shutdown).await;

        log_progress(
            start_time,
            &completed_urls,
            &failed_urls,
            Some(&total_urls_attempted),
        );

        let elapsed_seconds = start_time.elapsed().as_secs_f64();

        let total_urls = total_urls_attempted.load(Ordering::SeqCst) as i32;
        let successful_urls = completed_urls.load(Ordering::SeqCst) as i32;
        let failed_urls_count = failed_urls.load(Ordering::SeqCst) as i32;

        update_run_stats(
            &pool,
            &run_id,
            total_urls,
            successful_urls,
            failed_urls_count,
            elapsed_seconds,
        )
        .await
        .context("Failed to update run statistics")?;

        if let Err(e) = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(pool.as_ref())
            .await
        {
            log::warn!(
                "Failed to checkpoint WAL file (this is non-critical): {}",
                e
            );
        }

        print_error_statistics(&error_stats);

        if config.show_timing {
            let geoip_enabled = crate::geoip::is_enabled();
            print_timing_statistics(
                &timing_stats,
                Some(geoip_enabled),
                Some(config.enable_whois),
            );
        }

        Ok(ScanReport {
            total_urls: total_urls as usize,
            successful: successful_urls as usize,
            failed: failed_urls_count as usize,
            db_path: config.db_path.clone(),
            run_id,
            elapsed_seconds,
        })
    }
}
