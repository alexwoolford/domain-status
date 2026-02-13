//! Statistics printing and database updates.

use anyhow::{Context, Result};
use log::info;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use strum::IntoEnumIterator;

use crate::database;
use crate::error_handling::{ErrorType, InfoType, ProcessingStats, WarningType};
use crate::utils::TimingStats;

/// Prints final statistics and updates the database with run statistics.
///
/// This function is used internally by the library and in tests.
#[allow(dead_code)] // Used in tests
pub async fn print_and_save_final_statistics(
    pool: &sqlx::SqlitePool,
    run_id: &str,
    total_urls_attempted: &Arc<AtomicUsize>,
    completed_urls: &Arc<AtomicUsize>,
    failed_urls: &Arc<AtomicUsize>,
    error_stats: &Arc<ProcessingStats>,
    elapsed_seconds: f64,
) -> Result<()> {
    // Calculate run statistics
    // All tasks have completed at this point, so counters should be final
    // Safe casts: URL counts should be reasonable (< i32::MAX ~2B) for SQLite storage
    // Realistic usage scenarios won't exceed this limit
    #[allow(clippy::cast_possible_truncation)]
    let total_urls = total_urls_attempted.load(Ordering::SeqCst) as i32;
    #[allow(clippy::cast_possible_truncation)]
    let successful_urls = completed_urls.load(Ordering::SeqCst) as i32;
    // Use actual failed_urls counter instead of calculating it
    // This ensures accuracy even if there are pending URLs
    #[allow(clippy::cast_possible_truncation)]
    let failed_urls_count = failed_urls.load(Ordering::SeqCst) as i32;

    info!(
        "Run statistics: total={}, successful={}, failed={}",
        total_urls, successful_urls, failed_urls_count
    );

    // Update run statistics in database
    let stats = database::RunStats {
        run_id,
        total_urls,
        successful_urls,
        failed_urls: failed_urls_count,
        elapsed_seconds,
    };
    database::update_run_stats(pool, &stats)
        .await
        .context("Failed to update run statistics")?;

    // Print processing statistics
    print_error_statistics(error_stats);

    // Print simple one-line summary at the end
    print_simple_summary(
        total_urls,
        successful_urls,
        failed_urls_count,
        elapsed_seconds,
    );

    Ok(())
}

/// Prints a simple one-line summary of the run.
///
/// This provides immediate feedback to the user in a concise format.
/// Works with both plain and JSON log formats (log::info! handles formatting).
#[allow(dead_code)] // Used internally by print_and_save_final_statistics
fn print_simple_summary(
    total_urls: i32,
    successful_urls: i32,
    failed_urls: i32,
    elapsed_seconds: f64,
) {
    info!(
        "✅ Processed {} URL{} ({} succeeded, {} failed) in {:.1}s - see database for details",
        total_urls,
        if total_urls == 1 { "" } else { "s" },
        successful_urls,
        failed_urls,
        elapsed_seconds
    );
}

/// Prints timing statistics if enabled.
///
/// Optionally accepts flags to indicate whether GeoIP and WHOIS are enabled,
/// which will be displayed in the output when these features are disabled.
pub fn print_timing_statistics(
    timing_stats: &Arc<TimingStats>,
    geoip_enabled: Option<bool>,
    whois_enabled: Option<bool>,
) {
    timing_stats.log_summary(geoip_enabled, whois_enabled);
}

/// Prints error, warning, and info statistics to the log.
///
/// This function is used internally and in tests.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ProcessingStats;
    use crate::utils::TimingStats;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    #[test]
    fn test_print_error_statistics_no_errors() {
        let stats = ProcessingStats::new();
        // Should not panic when there are no errors
        print_error_statistics(&stats);
    }

    #[test]
    fn test_print_error_statistics_with_errors() {
        let stats = ProcessingStats::new();
        stats.increment_error(ErrorType::HttpRequestTimeoutError);
        stats.increment_error(ErrorType::HttpRequestTimeoutError);
        stats.increment_error(ErrorType::DnsNsLookupError);
        // Should not panic when there are errors
        print_error_statistics(&stats);
    }

    #[test]
    fn test_print_error_statistics_with_warnings() {
        let stats = ProcessingStats::new();
        stats.increment_warning(WarningType::MissingMetaDescription);
        stats.increment_warning(WarningType::MissingTitle);
        // Should not panic when there are warnings
        print_error_statistics(&stats);
    }

    #[test]
    fn test_print_error_statistics_with_info() {
        let stats = ProcessingStats::new();
        stats.increment_info(InfoType::HttpRedirect);
        stats.increment_info(InfoType::HttpsRedirect);
        // Should not panic when there are info metrics
        print_error_statistics(&stats);
    }

    #[test]
    fn test_print_error_statistics_all_types() {
        let stats = ProcessingStats::new();
        stats.increment_error(ErrorType::HttpRequestTimeoutError);
        stats.increment_warning(WarningType::MissingMetaDescription);
        stats.increment_info(InfoType::HttpRedirect);
        // Should handle all types together
        print_error_statistics(&stats);
    }

    #[test]
    fn test_print_timing_statistics() {
        let timing_stats = Arc::new(TimingStats::default());
        // Should not panic
        print_timing_statistics(&timing_stats, Some(true), Some(true));
        print_timing_statistics(&timing_stats, Some(false), Some(false));
        print_timing_statistics(&timing_stats, None, None);
    }

    #[tokio::test]
    async fn test_print_and_save_final_statistics() {
        // Create in-memory database for testing
        let pool = sqlx::SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create in-memory database");

        // Create tables (matching actual schema)
        sqlx::query(
            "CREATE TABLE runs (
                run_id TEXT PRIMARY KEY,
                version TEXT,
                start_time_ms INTEGER NOT NULL,
                end_time_ms INTEGER,
                total_urls INTEGER,
                successful_urls INTEGER,
                failed_urls INTEGER,
                elapsed_seconds REAL,
                fingerprints_source TEXT,
                fingerprints_version TEXT,
                geoip_version TEXT
            )",
        )
        .execute(&pool)
        .await
        .expect("Failed to create runs table");

        let run_id = "test-run-123";
        let total_urls = Arc::new(AtomicUsize::new(100));
        let completed_urls = Arc::new(AtomicUsize::new(85));
        let failed_urls = Arc::new(AtomicUsize::new(15));
        let error_stats = Arc::new(ProcessingStats::new());

        // Insert initial run record using insert_run_metadata
        use crate::storage::{insert_run_metadata, RunMetadata};
        let meta = RunMetadata {
            run_id,
            start_time_ms: chrono::Utc::now().timestamp_millis(),
            version: "0.1.4",
            fingerprints_source: None,
            fingerprints_version: None,
            geoip_version: None,
        };
        insert_run_metadata(&pool, &meta)
            .await
            .expect("Failed to insert run");

        // Call function
        let result = print_and_save_final_statistics(
            &pool,
            run_id,
            &total_urls,
            &completed_urls,
            &failed_urls,
            &error_stats,
            10.5, // elapsed_seconds for test
        )
        .await;

        assert!(result.is_ok(), "Function should succeed");

        // Verify statistics were updated
        let row = sqlx::query_as::<_, (i32, i32, i32)>(
            "SELECT total_urls, successful_urls, failed_urls FROM runs WHERE run_id = ?",
        )
        .bind(run_id)
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch run");

        assert_eq!(row.0, 100, "Total URLs should be 100");
        assert_eq!(row.1, 85, "Successful URLs should be 85");
        assert_eq!(row.2, 15, "Failed URLs should be 15 (100 - 85)");
    }

    #[tokio::test]
    async fn test_print_and_save_final_statistics_zero_urls() {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create in-memory database");

        sqlx::query(
            "CREATE TABLE runs (
                run_id TEXT PRIMARY KEY,
                version TEXT,
                start_time_ms INTEGER NOT NULL,
                end_time_ms INTEGER,
                total_urls INTEGER,
                successful_urls INTEGER,
                failed_urls INTEGER,
                elapsed_seconds REAL,
                fingerprints_source TEXT,
                fingerprints_version TEXT,
                geoip_version TEXT
            )",
        )
        .execute(&pool)
        .await
        .expect("Failed to create runs table");

        let run_id = "test-run-zero";
        let total_urls = Arc::new(AtomicUsize::new(0));
        let completed_urls = Arc::new(AtomicUsize::new(0));
        let failed_urls = Arc::new(AtomicUsize::new(0));
        let error_stats = Arc::new(ProcessingStats::new());

        // Insert initial run record using insert_run_metadata
        use crate::storage::{insert_run_metadata, RunMetadata};
        let meta = RunMetadata {
            run_id,
            start_time_ms: chrono::Utc::now().timestamp_millis(),
            version: "0.1.4",
            fingerprints_source: None,
            fingerprints_version: None,
            geoip_version: None,
        };
        insert_run_metadata(&pool, &meta)
            .await
            .expect("Failed to insert run");

        let result = print_and_save_final_statistics(
            &pool,
            run_id,
            &total_urls,
            &completed_urls,
            &failed_urls,
            &error_stats,
            0.0, // elapsed_seconds for test (zero URLs)
        )
        .await;

        assert!(result.is_ok(), "Function should succeed with zero URLs");
    }
}
