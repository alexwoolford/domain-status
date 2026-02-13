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
    } = loop_result;

    // Shutdown background tasks
    shutdown_gracefully(cancel, logging_task, resources.rate_limiter_shutdown).await;

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
    #[allow(clippy::cast_possible_truncation)]
    let total_urls = resources.total_urls_attempted.load(Ordering::SeqCst) as i32;
    #[allow(clippy::cast_possible_truncation)]
    let successful_urls = resources.completed_urls.load(Ordering::SeqCst) as i32;
    #[allow(clippy::cast_possible_truncation)]
    let failed_urls_count = resources.failed_urls.load(Ordering::SeqCst) as i32;

    // Update run statistics in database
    let stats = RunStats {
        run_id: &resources.run_id,
        total_urls,
        successful_urls,
        failed_urls: failed_urls_count,
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
        log::warn!(
            "Failed to checkpoint WAL file (this is non-critical): {}",
            e
        );
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
        db_path: resources.config.db_path.clone(),
        run_id: resources.run_id,
        elapsed_seconds,
    })
}
