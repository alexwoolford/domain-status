//! Scan finalization and cleanup.
//!
//! This module contains the `finalize_scan` function which handles
//! all cleanup and result aggregation after the main scan loop completes.

use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};

use crate::app::statistics::print_error_statistics;
use crate::app::{log_progress, print_timing_statistics, shutdown_gracefully};
use crate::storage::insert::{count_run_fact_rows, saturating_i32_count};
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
    resources
        .phase
        .set(crate::status_server::ScanPhase::Finalizing);

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

    // Log final progress against the input file total (not attempted-only).
    log_progress(
        resources.start_time,
        &resources.successful_urls,
        &resources.failed_urls,
        &resources.skipped_urls,
        Some(&resources.total_urls_in_file),
    );

    let elapsed_seconds = resources.start_time.elapsed().as_secs_f64();

    let FinalRunCounts {
        total_urls,
        successful_urls,
        failed_urls: failed_urls_count,
        skipped_urls: skipped_urls_count,
    } = persist_run_counts(
        resources.shared_ctx.pool.as_ref(),
        &resources.run_id,
        resources.total_urls_attempted.as_ref(),
        resources.successful_urls.as_ref(),
        resources.failed_urls.as_ref(),
        resources.skipped_urls.as_ref(),
        elapsed_seconds,
    )
    .await
    .context("Failed to update run statistics")?;

    // Checkpoint WAL file for clean database state
    if let Err(e) = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(resources.shared_ctx.pool.as_ref())
        .await
    {
        log::warn!("Failed to checkpoint WAL file (this is non-critical): {e}");
    }

    // Close database pool
    resources.shared_ctx.pool.close().await;
    log::debug!("Database pool closed");

    // Print statistics
    print_error_statistics(&resources.shared_ctx.runtime.error_stats);

    let geoip_enabled = crate::geoip::is_enabled();
    print_timing_statistics(
        &resources.shared_ctx.runtime.timing_stats,
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

struct FinalRunCounts {
    total_urls: i32,
    successful_urls: i32,
    failed_urls: i32,
    skipped_urls: i32,
}

/// Persist `runs` counters. Success/failure come from fact-table `COUNT(*)`;
/// skipped stays on the in-memory atomic (duplicate-domain skips never insert).
async fn persist_run_counts(
    pool: &sqlx::SqlitePool,
    run_id: &str,
    total_urls_attempted: &AtomicUsize,
    successful_urls: &AtomicUsize,
    failed_urls: &AtomicUsize,
    skipped_urls: &AtomicUsize,
    elapsed_seconds: f64,
) -> Result<FinalRunCounts> {
    // SAFETY: Cast from usize to i32 for database storage is acceptable here.
    // These casts represent URL counts processed in a single scan run:
    // 1. Practical limits: Even at 10,000 URLs/sec, processing 2.1B URLs would take 60+ hours
    // 2. Memory constraints: Processing billions of URLs would exhaust system memory first
    // 3. Database schema: SQLite uses INTEGER (i32) for these columns
    // 4. Realistic usage: Typical production runs process 100K-10M URLs, well within i32 range
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let total_urls = total_urls_attempted.load(Ordering::SeqCst) as i32;
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let atomic_successful = successful_urls.load(Ordering::SeqCst) as i32;
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let atomic_failed = failed_urls.load(Ordering::SeqCst) as i32;
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let skipped_urls = skipped_urls.load(Ordering::SeqCst) as i32;

    let facts = count_run_fact_rows(pool, run_id)
        .await
        .context("Failed to count url_status / url_failures for run")?;
    let successful_urls = saturating_i32_count(facts.successful_urls);
    let failed_urls = saturating_i32_count(facts.failed_urls);

    if facts.successful_urls != i64::from(atomic_successful) {
        log::warn!(
            "successful_urls atomic={} disagrees with url_status COUNT(*)={}; persisting fact-table count",
            atomic_successful,
            facts.successful_urls
        );
    }
    if facts.failed_urls != i64::from(atomic_failed) {
        log::warn!(
            "failed_urls atomic={} disagrees with url_failures COUNT(*)={}; persisting fact-table count",
            atomic_failed,
            facts.failed_urls
        );
    }

    let stats = RunStats {
        run_id,
        total_urls,
        successful_urls,
        failed_urls,
        skipped_urls,
        elapsed_seconds,
    };
    update_run_stats(pool, &stats)
        .await
        .context("Failed to update run statistics")?;

    Ok(FinalRunCounts {
        total_urls,
        successful_urls,
        failed_urls,
        skipped_urls,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    use crate::initialization::test_resolver;
    use tokio::sync::Semaphore;
    use tokio_util::sync::CancellationToken;

    use crate::config::Config;
    use crate::error_handling::ProcessingStats;
    use crate::fetch::{NetworkContext, ProcessingContext, RuntimeContext};
    use crate::fingerprint::FingerprintRuleset;
    use crate::runtime_metrics::RuntimeMetrics;
    use crate::storage::test_helpers::create_test_pool as create_test_sqlite_pool;
    use crate::storage::test_helpers::create_test_url_status;
    use crate::storage::{insert_run_metadata, RunMetadata};
    use crate::utils::TimingStats;

    use super::*;

    async fn create_test_pool() -> crate::storage::DbPool {
        Arc::new(create_test_sqlite_pool().await)
    }

    async fn insert_test_run(pool: &sqlx::SqlitePool, run_id: &str) {
        insert_run_metadata(
            pool,
            &RunMetadata {
                run_id,
                start_time_ms: 1_704_067_200_000_i64,
                version: "0.1.0",
                fingerprints_source: Some("test"),
                fingerprints_version: Some("0"),
                geoip_version: None,
            },
        )
        .await
        .expect("insert run metadata");
    }

    async fn seed_url_status_rows(pool: &sqlx::SqlitePool, run_id: &str, count: usize) {
        for i in 0..count {
            let domain = format!("ok{i}.example.com");
            create_test_url_status(pool, &domain, &domain, 200, Some(run_id), 1).await;
        }
    }

    async fn seed_url_failure_rows(pool: &sqlx::SqlitePool, run_id: &str, count: usize) {
        for i in 0..count {
            let domain = format!("fail{i}.example.com");
            sqlx::query(
                "INSERT INTO url_failures (
                    attempted_url, initial_domain, error_type, error_message,
                    retry_count, observed_at_ms, run_id
                ) VALUES (?, ?, 'timeout', 'timed out', 0, 1, ?)",
            )
            .bind(format!("https://{domain}/"))
            .bind(&domain)
            .bind(run_id)
            .execute(pool)
            .await
            .expect("insert url_failures row");
        }
    }

    async fn finalize_resources(
        pool: crate::storage::DbPool,
        run_id: &str,
        attempted: usize,
        atomic_success: usize,
        atomic_failed: usize,
        atomic_skipped: usize,
    ) -> (ScanResources, ScanLoopResult) {
        let start_time_ms = 1_704_067_200_000_i64;
        let client = Arc::new(reqwest::Client::builder().build().expect("http client"));
        let redirect_client = Arc::new(
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("redirect client"),
        );
        let error_stats = Arc::new(ProcessingStats::new());
        let timing_stats = Arc::new(TimingStats::new());
        let shared_ctx = Arc::new(ProcessingContext::new(
            NetworkContext::new(client, redirect_client, test_resolver()),
            Arc::clone(&pool),
            RuntimeContext::new(
                Arc::clone(&error_stats),
                Arc::clone(&timing_stats),
                Some(run_id.to_string()),
                false,
                std::path::PathBuf::from("/tmp/domain_status_whois_test"),
                false,
                Arc::new(RuntimeMetrics::default()),
                true,
            ),
            Arc::new(FingerprintRuleset::empty_for_tests()),
        ));

        let resources = ScanResources {
            shared_ctx,
            semaphore: Arc::new(Semaphore::new(1)),
            request_limiter: None,
            rate_limiter_shutdown: None,
            in_flight_urls: Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())),
            successful_urls: Arc::new(AtomicUsize::new(atomic_success)),
            skipped_urls: Arc::new(AtomicUsize::new(atomic_skipped)),
            failed_urls: Arc::new(AtomicUsize::new(atomic_failed)),
            total_urls_attempted: Arc::new(AtomicUsize::new(attempted)),
            total_urls_in_file: Arc::new(AtomicUsize::new(attempted)),
            phase: Arc::new(crate::status_server::AtomicPhase::default()),
            throughput_window: Arc::new(crate::status_server::ThroughputWindow::new()),
            run_id: run_id.to_string(),
            start_time_epoch: start_time_ms,
            start_time: std::time::Instant::now(),
            _geoip_metadata: None,
            config: Config {
                db_path: std::path::PathBuf::from(":memory:"),
                enable_whois: false,
                cache_dir: None,
                scan_external_scripts: false,
                ..Config::default()
            },
        };
        let loop_result = ScanLoopResult {
            cancel: CancellationToken::new(),
            logging_task: None,
            status_server: None,
        };
        (resources, loop_result)
    }

    /// `finalize_scan` returns a `ScanReport` with fact-table success/failure counts.
    #[tokio::test]
    async fn test_finalize_scan_returns_correct_report() {
        let pool = create_test_pool().await;
        let run_id = "run_finalize_test_123";
        insert_test_run(pool.as_ref(), run_id).await;
        seed_url_status_rows(pool.as_ref(), run_id, 8).await;
        seed_url_failure_rows(pool.as_ref(), run_id, 2).await;
        let (resources, loop_result) = finalize_resources(pool, run_id, 10, 8, 2, 0).await;

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

    #[tokio::test]
    async fn test_finalize_scan_persists_fact_counts_when_atomics_disagree() {
        let pool = create_test_pool().await;
        let run_id = "run_finalize_disagree";
        insert_test_run(pool.as_ref(), run_id).await;
        seed_url_status_rows(pool.as_ref(), run_id, 3).await;
        seed_url_failure_rows(pool.as_ref(), run_id, 1).await;
        let (resources, loop_result) = finalize_resources(pool, run_id, 10, 8, 2, 4).await;

        let report = finalize_scan(resources, loop_result)
            .await
            .expect("finalize_scan should succeed");

        assert_eq!(report.total_urls, 10);
        assert_eq!(report.successful, 3);
        assert_eq!(report.failed, 1);
        assert_eq!(report.skipped, 4);
    }
}
