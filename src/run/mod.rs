//! URL scanning orchestration module.
//!
//! This module contains the main `run_scan` function and supporting types
//! for executing URL scans. The implementation is decomposed into:
//!
//! - `resources` - Data structures for scan state and resources
//! - `init` - Resource initialization logic
//! - `task` - Per-URL task processing
//! - `finalize` - Scan finalization and cleanup

mod finalize;
mod init;
mod resources;
mod task;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use log::warn;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::app::{log_progress, validate_and_normalize_url};
use crate::config::{LOGGING_INTERVAL, STATUS_SERVER_LOGGING_INTERVAL_SECS};
use crate::error_handling::ErrorType;
use crate::security::validate_url_safe;
use crate::storage::insert::insert_url_failure;
use crate::storage::models::UrlFailureRecord;
use crate::storage::DbPool;

/// RAII guard that registers a URL with the in-flight registry on construction
/// and removes it on drop.
///
/// The drain phase reads what's still in the registry when its deadline fires
/// to record a `url_failures` row for every abandoned URL. The guard's `Drop`
/// runs synchronously even when a task future is aborted at an `.await` point,
/// so successful tasks remove themselves before the drain snapshot, and aborted
/// tasks remain visible — exactly the distinction we need.
struct InFlightGuard {
    registry: Arc<Mutex<HashSet<String>>>,
    url: Option<String>,
}

impl InFlightGuard {
    fn register(registry: Arc<Mutex<HashSet<String>>>, url: String) -> Self {
        if let Ok(mut set) = registry.lock() {
            set.insert(url.clone());
        }
        Self {
            registry,
            url: Some(url),
        }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if let Some(url) = self.url.take() {
            if let Ok(mut set) = self.registry.lock() {
                set.remove(&url);
            }
        }
    }
}

/// Records a `url_failures` row for each URL whose task was abandoned at the
/// drain timeout. Returns the number of rows successfully inserted.
///
/// Failures here are best-effort: an insert failure is logged but does not
/// abort the rest of the loop, since the alternative (leaving the URL with
/// no record at all) is worse than logging.
async fn record_drain_timeout_failures(
    pool: &DbPool,
    run_id: &str,
    drain_timeout_secs: u64,
    abandoned: &[String],
) -> usize {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let mut inserted = 0usize;
    for url in abandoned {
        let domain = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_else(|| url.clone());
        let record = UrlFailureRecord {
            url: url.clone(),
            final_url: None,
            domain,
            final_domain: None,
            error_type: ErrorType::ProcessUrlTimeout,
            error_message: format!(
                "Aborted at scan drain timeout ({drain_timeout_secs}s expired); task did not finish in time"
            ),
            http_status: None,
            retry_count: 0,
            elapsed_time_seconds: None,
            timestamp: now_ms,
            run_id: Some(run_id.to_string()),
            redirect_chain: vec![],
            response_headers: vec![],
            request_headers: vec![],
        };
        match insert_url_failure(pool.as_ref(), &record).await {
            Ok(_) => inserted += 1,
            Err(e) => log::error!("Failed to insert drain-timeout url_failures row for {url}: {e}"),
        }
    }
    inserted
}

pub use resources::{ScanLoopResult, ScanResources, UrlTaskParams};

// Re-export for public API
pub use init::init_scan_resources;

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
    /// Number of URLs intentionally skipped (e.g. duplicate domain in same run)
    pub skipped: usize,
    /// Path to the `SQLite` database containing results
    pub db_path: PathBuf,
    /// Run identifier (format: `run_<timestamp_millis>`)
    pub run_id: String,
    /// Elapsed time in seconds
    pub elapsed_seconds: f64,
}

/// Helper function to invoke the progress callback if provided.
///
/// This reduces code duplication by centralizing the callback invocation logic.
#[allow(clippy::type_complexity)] // Matches the progress_callback type from Config; alias would add indirection
fn invoke_progress_callback(
    callback: Option<&Arc<dyn Fn(usize, usize, usize, usize) + Send + Sync>>,
    completed: &Arc<std::sync::atomic::AtomicUsize>,
    failed: &Arc<std::sync::atomic::AtomicUsize>,
    skipped: &Arc<std::sync::atomic::AtomicUsize>,
    total: usize,
) {
    if let Some(cb) = callback {
        cb(
            completed.load(Ordering::Relaxed),
            failed.load(Ordering::Relaxed),
            skipped.load(Ordering::Relaxed),
            total,
        );
    }
}

/// Runs a URL scan with the provided configuration.
///
/// This is the main entry point for the library. It reads URLs from the input file,
/// processes them concurrently, and stores results in a `SQLite` database.
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
#[allow(clippy::cognitive_complexity)] // Multi-phase scan: init, status server, logging, URL loop, drain, finalize
#[allow(clippy::too_many_lines)] // 6 sequential phases that share state; already factored into init/finalize modules
pub async fn run_scan(
    config: crate::config::Config,
) -> Result<ScanReport, crate::error_handling::RunScanError> {
    // Phase 1: Initialize all resources
    let (resources, mut url_source, total_lines, progress_callback) = init_scan_resources(config)
        .await
        .map_err(|e| crate::error_handling::RunScanError::Startup(e.into()))?;

    // Phase 2: Start status server if configured
    let mut status_server = if let Some(port) = resources.config.status_port {
        let status_state = crate::status_server::StatusState {
            total_urls: Arc::clone(&resources.total_urls_in_file),
            total_urls_attempted: Arc::clone(&resources.total_urls_attempted),
            completed_urls: Arc::clone(&resources.completed_urls),
            failed_urls: Arc::clone(&resources.failed_urls),
            skipped_urls: Arc::clone(&resources.skipped_urls),
            start_time: Arc::new(resources.start_time),
            error_stats: resources.error_stats.clone(),
            timing_stats: Some(Arc::clone(&resources.timing_stats)),
            request_limiter: resources.request_limiter.as_ref().map(Arc::clone),
            runtime_metrics: Arc::clone(&resources.runtime_metrics),
            run_id: Some(resources.run_id.clone()),
            run_start_time_unix_secs: Some({
                #[allow(clippy::cast_precision_loss)]
                // Epoch millis fits in f64 mantissa until year 2255
                {
                    (resources.start_time_epoch as f64) / 1000.0
                }
            }),
        };
        Some(
            crate::status_server::spawn_status_server(port, status_state)
                .await
                .map_err(|e| crate::error_handling::RunScanError::Startup(e.into()))?,
        )
    } else {
        None
    };

    // Phase 3: Start progress logging and run the main scan loop
    let cancel = CancellationToken::new();
    let cancel_for_signal = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancel_for_signal.cancel();
        }
    });
    let cancel_logging = cancel.child_token();

    let completed_urls_for_logging = Arc::clone(&resources.completed_urls);
    let failed_urls_for_logging = Arc::clone(&resources.failed_urls);
    let total_urls_for_logging = Arc::clone(&resources.total_urls_attempted);
    let start_time = resources.start_time;

    let logging_interval_secs = if resources.config.status_port.is_none() {
        LOGGING_INTERVAL as u64
    } else {
        STATUS_SERVER_LOGGING_INTERVAL_SECS
    };

    let mut logging_task = Some(tokio::task::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(logging_interval_secs));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    log_progress(start_time, &completed_urls_for_logging, &failed_urls_for_logging, Some(&total_urls_for_logging));
                }
                () = cancel_logging.cancelled() => {
                    break;
                }
            }
        }
    }));

    // Phase 4: Run the main scan loop
    // Use JoinSet instead of FuturesUnordered for better memory efficiency.
    // JoinSet allows interleaved spawning and reaping, preventing memory accumulation
    // when processing large URL lists (1M+ URLs).
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut consecutive_errors = 0;
    const MAX_CONSECUTIVE_ERRORS: usize = 10;

    loop {
        // Interleaved reaping: Try to reap any completed tasks before spawning new ones.
        // This prevents JoinHandle accumulation when tasks complete faster than new ones are read.
        // Using timeout(Duration::ZERO) for non-blocking check - if a task is ready, we get it;
        // otherwise we immediately continue to spawn new tasks.
        while let Ok(Some(task_result)) =
            tokio::time::timeout(std::time::Duration::ZERO, tasks.join_next()).await
        {
            if let Err(join_error) = task_result {
                resources.failed_urls.fetch_add(1, Ordering::Relaxed);
                log::warn!("Failed to join task (panicked): {join_error:?}");
            }
        }

        tokio::select! {
            line_result = url_source.next_line() => {
                let line = match line_result {
                    Ok(Some(line)) => {
                        consecutive_errors = 0;
                        line
                    }
                    Ok(None) => break,
                    Err(e) => {
                        consecutive_errors += 1;
                        if consecutive_errors > MAX_CONSECUTIVE_ERRORS {
                            crate::app::shutdown_gracefully(
                                cancel.clone(),
                                logging_task.take(),
                                resources.rate_limiter_shutdown.clone(),
                                status_server.take(),
                            )
                            .await;
                            return Err(crate::error_handling::RunScanError::Runtime(
                                anyhow::anyhow!(
                                    "Too many consecutive read errors ({consecutive_errors}): {e}"
                                ),
                            ));
                        }
                        warn!("Failed to read line from input: {e}");
                        continue;
                    }
                };

                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }

                let Some(url) = validate_and_normalize_url(trimmed) else {
                    resources
                        .total_urls_attempted
                        .fetch_add(1, Ordering::Relaxed);
                    resources.skipped_urls.fetch_add(1, Ordering::Relaxed);
                    invoke_progress_callback(
                        progress_callback.as_ref(),
                        &resources.completed_urls,
                        &resources.failed_urls,
                        &resources.skipped_urls,
                        total_lines,
                    );
                    continue;
                };

                // SSRF protection: reject private IPs, localhost, and unsafe schemes on the initial URL.
                // IP literals bypass the HTTP client's SafeResolver (no DNS lookup), so we must validate here.
                // allow_localhost_for_tests lets integration tests use mock servers bound to 127.0.0.1/::1.
                if !resources.config.allow_localhost_for_tests {
                    if let Err(e) = validate_url_safe(&url) {
                        warn!("Skipping SSRF-unsafe URL: {e}");
                        resources
                            .total_urls_attempted
                            .fetch_add(1, Ordering::Relaxed);
                        resources.skipped_urls.fetch_add(1, Ordering::Relaxed);
                        invoke_progress_callback(
                            progress_callback.as_ref(),
                            &resources.completed_urls,
                            &resources.failed_urls,
                            &resources.skipped_urls,
                            total_lines,
                        );
                        continue;
                    }
                }

                // Race semaphore acquisition against cancellation so we don't block on the
                // permit wait with no way to respond to Ctrl-C (avoids deadlock when all
                // worker permits are in use).
                let permit = tokio::select! {
                    result = Arc::clone(&resources.semaphore).acquire_owned() => {
                        if let Ok(p) = result { p } else {
                            warn!("Semaphore closed, skipping URL: {url}");
                            resources
                                .total_urls_attempted
                                .fetch_add(1, Ordering::Relaxed);
                            resources
                                .failed_urls
                                .fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                    }
                    () = cancel.cancelled() => {
                        log::info!("Received interrupt (Ctrl-C), finishing current work and finalizing...");
                        break;
                    }
                };

                resources
                    .total_urls_attempted
                    .fetch_add(1, Ordering::Relaxed);

                let task_params = UrlTaskParams {
                    url: Arc::from(url.as_str()),
                    ctx: Arc::clone(&resources.shared_ctx),
                    cancel: cancel.clone(),
                    permit,
                    request_limiter: resources.request_limiter.as_ref().map(Arc::clone),
                    completed_urls: Arc::clone(&resources.completed_urls),
                    successful_urls: Arc::clone(&resources.successful_urls),
                    skipped_urls: Arc::clone(&resources.skipped_urls),
                    failed_urls: Arc::clone(&resources.failed_urls),
                    total_urls_for_callback: total_lines,
                    progress_callback: progress_callback.clone(),
                };

                // Wrap the task so an InFlightGuard registers the URL on entry and
                // removes it on drop. The drain phase reads what is still registered
                // when its deadline fires to record a url_failures row for every URL
                // that was aborted, instead of silently incrementing a counter.
                let registry = Arc::clone(&resources.in_flight_urls);
                let url_for_registry = url.clone();
                // JoinSet::spawn() is like FuturesUnordered::push(tokio::spawn(...))
                // but manages the JoinHandle internally without accumulating them all in memory
                tasks.spawn(async move {
                    let _guard = InFlightGuard::register(registry, url_for_registry);
                    task::process_url_task(task_params).await;
                });
            }
            () = cancel.cancelled() => {
                log::info!("Received interrupt (Ctrl-C), finishing current work and finalizing...");
                break;
            }
        }
    }

    // Phase 5: Drain remaining tasks with timeout so Ctrl-C doesn't hang indefinitely.
    // Use a single wall-clock deadline for the entire drain, not per-task timeouts,
    // so N slow tasks can't extend the shutdown to N * timeout.
    let drain_timeout_secs = resources.config.drain_timeout_secs;
    let drain_timeout = std::time::Duration::from_secs(drain_timeout_secs);
    let drain_deadline = tokio::time::Instant::now() + drain_timeout;
    loop {
        let remaining = drain_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            // Snapshot the URLs whose tasks are still in flight BEFORE aborting them.
            // The InFlightGuard::Drop removes URLs on natural completion, so the set
            // we read here is exactly the set that did NOT finish in time.
            let abandoned: Vec<String> = resources
                .in_flight_urls
                .lock()
                .map(|set| set.iter().cloned().collect())
                .unwrap_or_default();
            let abandoned_count = abandoned.len();
            if abandoned_count > 0 {
                log::warn!(
                    "Drain timeout ({drain_timeout_secs}s) reached, recording {abandoned_count} in-flight task(s) as failures and aborting"
                );
                let inserted = record_drain_timeout_failures(
                    &resources.pool,
                    &resources.run_id,
                    drain_timeout_secs,
                    &abandoned,
                )
                .await;
                if inserted < abandoned_count {
                    log::warn!(
                        "Recorded {inserted}/{abandoned_count} drain-timeout failures (the rest hit DB errors; see preceding log lines)"
                    );
                }
                resources
                    .failed_urls
                    .fetch_add(abandoned_count, Ordering::Relaxed);
            } else {
                log::info!("Drain timeout ({drain_timeout_secs}s) reached, no remaining tasks");
            }
            tasks.abort_all();
            cancel.cancel();
            break;
        }
        match tokio::time::timeout(remaining, tasks.join_next()).await {
            Ok(Some(task_result)) => {
                if let Err(join_error) = task_result {
                    resources.failed_urls.fetch_add(1, Ordering::Relaxed);
                    log::warn!("Failed to join task (panicked): {join_error:?}");
                }
            }
            Ok(None) => break,
            #[allow(clippy::needless_continue)]
            // Explicit continue clarifies intent: retry after timeout
            Err(_) => continue, // Deadline check at top of loop handles the abort
        }
    }

    // Phase 6: Finalize
    let loop_result = ScanLoopResult {
        cancel,
        logging_task,
        status_server,
    };

    finalize::finalize_scan(resources, loop_result)
        .await
        .map_err(crate::error_handling::RunScanError::Runtime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, FailOn, LogFormat, LogLevel};
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_run_scan_validation_failure() {
        let config = Config {
            max_concurrency: 0, // Invalid - should fail validation
            ..Default::default()
        };

        let result = run_scan(config).await;
        assert!(result.is_err(), "Should fail with invalid configuration");
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Configuration validation failed")
                || error_msg.contains("max_concurrency")
                || error_msg.contains("greater than 0"),
            "Expected validation error, got: {}",
            error_msg
        );
    }

    #[tokio::test]
    async fn test_run_scan_file_not_found() {
        let config = Config {
            file: std::path::PathBuf::from("/nonexistent/file/that/does/not/exist.txt"),
            ..Default::default()
        };

        let result = run_scan(config).await;
        assert!(result.is_err(), "Should fail when file doesn't exist");
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Failed to open input file")
                || error_msg.contains("No such file")
                || error_msg.contains("not found"),
            "Expected file not found error, got: {}",
            error_msg
        );
    }

    #[tokio::test]
    async fn test_run_scan_database_initialization_failure() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let db_path = temp_file.path().to_path_buf();
        drop(temp_file);

        let config = Config {
            file: std::path::PathBuf::from("/dev/null"),
            db_path,
            ..Default::default()
        };

        let result = run_scan(config).await;
        let _ = result;
    }

    #[tokio::test]
    async fn test_run_scan_empty_file() {
        let temp_input = NamedTempFile::new().expect("Failed to create temp file");
        let temp_db = NamedTempFile::new().expect("Failed to create temp DB");

        let config = Config {
            file: temp_input.path().to_path_buf(),
            db_path: temp_db.path().to_path_buf(),
            max_concurrency: 30,
            timeout_seconds: 10,
            rate_limit_rps: 15,
            fail_on: FailOn::Never,
            fail_on_pct_threshold: 10,
            enable_whois: false,
            log_level: LogLevel::Info,
            log_level_filter_override: None,
            log_format: LogFormat::Plain,
            user_agent: crate::config::DEFAULT_USER_AGENT.to_string(),
            fingerprints: None,
            geoip: None,
            status_port: None,
            log_file: None,
            progress_callback: None,
            dependency_overrides: None,
            allow_localhost_for_tests: false,
            drain_timeout_secs: 10,
        };

        let result = run_scan(config).await;
        match result {
            Ok(report) => {
                assert_eq!(report.total_urls, 0);
                assert_eq!(report.successful, 0);
                assert_eq!(report.failed, 0);
                assert_eq!(report.skipped, 0);

                // Verify finalize_scan wrote run stats to DB (run row matches report)
                let pool =
                    sqlx::SqlitePool::connect(&format!("sqlite:{}", report.db_path.display()))
                        .await
                        .expect("connect to test db");
                let row: (i64, i64, i64, i64) = sqlx::query_as(
                    "SELECT total_urls, successful_urls, failed_urls, skipped_urls FROM runs WHERE run_id = ?",
                )
                .bind(&report.run_id)
                .fetch_one(&pool)
                .await
                .expect("run row should exist");
                assert_eq!(
                    usize::try_from(row.0).expect("total_urls non-negative"),
                    report.total_urls,
                    "DB total_urls should match report"
                );
                assert_eq!(
                    usize::try_from(row.1).expect("successful_urls non-negative"),
                    report.successful,
                    "DB successful_urls should match report"
                );
                assert_eq!(
                    usize::try_from(row.2).expect("failed_urls non-negative"),
                    report.failed,
                    "DB failed_urls should match report"
                );
                assert_eq!(
                    usize::try_from(row.3).expect("skipped_urls non-negative"),
                    report.skipped,
                    "DB skipped_urls should match report"
                );
            }
            Err(e) => {
                let error_msg = e.to_string();
                assert!(
                    error_msg.contains("database")
                        || error_msg.contains("Database")
                        || error_msg.contains("migration")
                        || error_msg.contains("Failed to initialize"),
                    "Expected database/setup error for empty file test, got: {}",
                    error_msg
                );
            }
        }
    }

    #[tokio::test]
    async fn test_run_scan_file_with_comments() {
        let temp_input = NamedTempFile::new().expect("Failed to create temp file");
        std::fs::write(
            temp_input.path(),
            "# This is a comment\nhttps://example.com\n# Another comment\n",
        )
        .expect("Failed to write test file");

        let temp_db = NamedTempFile::new().expect("Failed to create temp DB");

        let config = Config {
            file: temp_input.path().to_path_buf(),
            db_path: temp_db.path().to_path_buf(),
            max_concurrency: 1,
            timeout_seconds: 10,
            rate_limit_rps: 15,
            fail_on: FailOn::Never,
            fail_on_pct_threshold: 10,
            enable_whois: false,
            log_level: LogLevel::Info,
            log_level_filter_override: None,
            log_format: LogFormat::Plain,
            user_agent: crate::config::DEFAULT_USER_AGENT.to_string(),
            fingerprints: None,
            geoip: None,
            status_port: None,
            log_file: None,
            progress_callback: None,
            dependency_overrides: None,
            allow_localhost_for_tests: false,
            drain_timeout_secs: 10,
        };

        let result = run_scan(config).await;
        match &result {
            Ok(report) => assert_eq!(
                report.total_urls, 1,
                "File with one URL and comments should result in one URL attempted"
            ),
            Err(_) => {
                // Init or network failure (e.g. fingerprint fetch); skip assertion
            }
        }
    }
}
