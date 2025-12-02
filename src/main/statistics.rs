//! Statistics printing and database updates.

use anyhow::{Context, Result};
use log::info;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use strum::IntoEnumIterator;

use crate::error_handling::{ErrorType, InfoType, ProcessingStats, WarningType};
use crate::database;

/// Prints final statistics and updates the database with run statistics.
pub async fn print_and_save_final_statistics(
    pool: &sqlx::SqlitePool,
    run_id: &str,
    total_urls_attempted: &Arc<AtomicUsize>,
    completed_urls: &Arc<AtomicUsize>,
    error_stats: &Arc<ProcessingStats>,
) -> Result<()> {
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
    database::update_run_stats(pool, run_id, total_urls, successful_urls, failed_urls)
        .await
        .context("Failed to update run statistics")?;

    // Print processing statistics
    print_error_statistics(error_stats);

    Ok(())
}

/// Prints error, warning, and info statistics to the log.
pub fn print_error_statistics(error_stats: &ProcessingStats) {
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
}

