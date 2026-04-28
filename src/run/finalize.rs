//! Scan finalization and cleanup.
//!
//! This module contains the `finalize_scan` function which handles
//! all cleanup and result aggregation after the main scan loop completes.

use std::sync::atomic::Ordering;

use anyhow::{Context, Result};

use crate::app::statistics::print_error_statistics;
use crate::app::{log_progress, print_timing_statistics, shutdown_gracefully};
use crate::storage::{update_run_stats, RunStats};

use super::{ScanLoopResult, ScanReport, ScanResources};

/// Finalize a scan run and produce the final report.
///
/// This function performs the following finalization steps:
/// 1. Shut down logging and rate limiter tasks
/// 2. Log final progress
/// 3. Update run statistics in database
/// 4. Checkpoint WAL file
/// 5. Close database pool
/// 6. Print error and timing statistics
/// 7. Construct and return the scan report
///
/// # Arguments
///
/// * `resources` - All scan resources (will be consumed)
/// * `loop_result` - Result from the scan loop (cancellation token, logging task)
///
/// # Returns
///
/// Returns a `ScanReport` with final statistics.
///
/// # Errors
///
/// Returns an error if database operations fail.
pub async fn finalize_scan(
    resources: ScanResources,
    loop_result: ScanLoopResult,
) -> Result<ScanReport> {
    let ScanLoopResult {
        cancel,
        logging_task,
        status_server,
    } = loop_result;

    // Shutdown background tasks
    shutdown_gracefully(
        cancel,
        logging_task,
        resources.rate_limiter_shutdown,
        status_server,
    )
    .await;

    // Log final progress
    log_progress(
        resources.start_time,
        &resources.completed_urls,
        &resources.failed_urls,
        Some(&resources.total_urls_attempted),
    );

    let elapsed_seconds = resources.start_time.elapsed().as_secs_f64();

    // SAFETY: Cast from usize to i32 for database storage is acceptable here.
    // These casts represent URL counts processed in a single scan run:
    // 1. Practical limits: Even at 10,000 URLs/sec, processing 2.1B URLs would take 60+ hours
    // 2. Memory constraints: Processing billions of URLs would exhaust system memory first
    // 3. Database schema: SQLite uses INTEGER (i32) for these columns
    // 4. Realistic usage: Typical production runs process 100K-10M URLs, well within i32 range
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let total_urls = resources.total_urls_attempted.load(Ordering::SeqCst) as i32;
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let successful_urls = resources.successful_urls.load(Ordering::SeqCst) as i32;
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let failed_urls_count = resources.failed_urls.load(Ordering::SeqCst) as i32;
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let skipped_urls_count = resources.skipped_urls.load(Ordering::SeqCst) as i32;

    // Update run statistics in database
    let stats = RunStats {
        run_id: &resources.run_id,
        total_urls,
        successful_urls,
        failed_urls: failed_urls_count,
        skipped_urls: skipped_urls_count,
        elapsed_seconds,
    };
    update_run_stats(&resources.pool, &stats)
        .await
        .context("Failed to update run statistics")?;

    // Checkpoint WAL file for clean database state
    if let Err(e) = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(resources.pool.as_ref())
        .await
    {
        log::warn!("Failed to checkpoint WAL file (this is non-critical): {e}");
    }

    // Close database pool
    resources.pool.close().await;
    log::debug!("Database pool closed");

    // Print statistics
    print_error_statistics(&resources.error_stats);

    let geoip_enabled = crate::geoip::is_enabled();
    print_timing_statistics(
        &resources.timing_stats,
        Some(geoip_enabled),
        Some(resources.config.enable_whois),
    );

    // SAFETY: Cast from i32 back to usize for API consistency is safe here.
    // These values came from usize counters and were cast to i32 for database storage.
    // Sign loss cannot occur because URL counts are always non-negative.
    #[allow(clippy::cast_sign_loss)]
    Ok(ScanReport {
        total_urls: total_urls as usize,
        #[allow(clippy::cast_sign_loss)]
        successful: successful_urls as usize,
        #[allow(clippy::cast_sign_loss)]
        failed: failed_urls_count as usize,
        #[allow(clippy::cast_sign_loss)]
        skipped: skipped_urls_count as usize,
        db_path: resources.config.db_path.clone(),
        run_id: resources.run_id,
        elapsed_seconds,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use std::time::SystemTime;

    use hickory_resolver::config::ResolverOpts;
    use hickory_resolver::TokioResolver;
    use tokio::sync::Semaphore;
    use tokio_util::sync::CancellationToken;

    use crate::config::Config;
    use crate::error_handling::ProcessingStats;
    use crate::fetch::{ConfigContext, DatabaseContext, NetworkContext, ProcessingContext};
    use crate::fingerprint::{FingerprintMetadata, FingerprintRuleset};
    use crate::runtime_metrics::RuntimeMetrics;
    use crate::storage::{insert_run_metadata, run_migrations, RunMetadata};
    use crate::utils::TimingStats;

    use super::*;

    async fn create_test_pool() -> crate::storage::DbPool {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:")
            .await
            .expect("test pool");
        run_migrations(&pool).await.expect("migrations");
        Arc::new(pool)
    }

    /// `finalize_scan` returns a `ScanReport` with correct totals and `run_id`; does not panic.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_finalize_scan_returns_correct_report() {
        let pool = create_test_pool().await;
        let run_id = "run_finalize_test_123";
        let start_time_ms = 1704067200000i64;
        let meta = RunMetadata {
            run_id,
            start_time_ms,
            version: "0.1.0",
            fingerprints_source: Some("test"),
            fingerprints_version: Some("0"),
            geoip_version: None,
        };
        insert_run_metadata(pool.as_ref(), &meta)
            .await
            .expect("insert run metadata");

        let total_urls_attempted = Arc::new(AtomicUsize::new(10));
        let completed_urls = Arc::new(AtomicUsize::new(8));
        let successful_urls = Arc::new(AtomicUsize::new(8));
        let skipped_urls = Arc::new(AtomicUsize::new(0));
        let failed_urls = Arc::new(AtomicUsize::new(2));
        let start_time = std::time::Instant::now();
        let error_stats = Arc::new(ProcessingStats::new());
        let timing_stats = Arc::new(TimingStats::new());

        let client = Arc::new(reqwest::Client::builder().build().expect("http client"));
        let redirect_client = Arc::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("redirect client"),
        );
        let extractor = Arc::new(psl::List);
        let resolver = Arc::new(
            TokioResolver::builder_tokio()
                .unwrap()
                .with_options(ResolverOpts::default())
                .build(),
        );

        let shared_ctx = Arc::new(ProcessingContext::new(
            NetworkContext::new(client, redirect_client, extractor, resolver),
            DatabaseContext::new(Arc::clone(&pool)),
            ConfigContext::new(
                Arc::clone(&error_stats),
                Arc::clone(&timing_stats),
                Some(run_id.to_string()),
                false,
                false,
                Arc::new(RuntimeMetrics::default()),
                true,
            ),
        ));

        let ruleset = Arc::new(FingerprintRuleset {
            technologies: HashMap::new(),
            categories: HashMap::new(),
            metadata: FingerprintMetadata {
                source: "test".into(),
                version: "0".into(),
                last_updated: SystemTime::now(),
            },
        });

        let config = Config {
            db_path: std::path::PathBuf::from(":memory:"),
            enable_whois: false,
            scan_external_scripts: false,
            ..Config::default()
        };

        let resources = ScanResources {
            pool,
            shared_ctx,
            semaphore: Arc::new(Semaphore::new(1)),
            request_limiter: None,
            rate_limiter_shutdown: None,
            error_stats,
            timing_stats,
            runtime_metrics: Arc::new(RuntimeMetrics::default()),
            in_flight_urls: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            completed_urls,
            successful_urls,
            skipped_urls,
            failed_urls,
            total_urls_attempted,
            total_urls_in_file: Arc::new(AtomicUsize::new(10)),
            run_id: run_id.to_string(),
            start_time_epoch: start_time_ms,
            start_time,
            _ruleset: ruleset,
            _geoip_metadata: None,
            config,
        };

        let cancel = CancellationToken::new();
        let loop_result = ScanLoopResult {
            cancel,
            logging_task: None,
            status_server: None,
        };

        let report = finalize_scan(resources, loop_result)
            .await
            .expect("finalize_scan should succeed");

        assert_eq!(report.total_urls, 10);
        assert_eq!(report.successful, 8);
        assert_eq!(report.failed, 2);
        assert_eq!(report.skipped, 0);
        assert_eq!(report.run_id, run_id);
        assert!(report.elapsed_seconds >= 0.0);
    }
}
