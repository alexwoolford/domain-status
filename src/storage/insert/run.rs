//! Run metadata insertion.
//!
//! This module handles inserting and updating run-level metadata and statistics.

use sqlx::{Row, SqlitePool};

use crate::error_handling::DatabaseError;

/// Metadata for a scan run, recorded at start.
pub struct RunMetadata<'a> {
    pub run_id: &'a str,
    pub start_time_ms: i64,
    pub version: &'a str,
    pub fingerprints_source: Option<&'a str>,
    pub fingerprints_version: Option<&'a str>,
    pub geoip_version: Option<&'a str>,
}

/// Statistics for a completed scan run, recorded at end.
pub struct RunStats<'a> {
    pub run_id: &'a str,
    pub total_urls: i32,
    pub successful_urls: i32,
    pub failed_urls: i32,
    pub elapsed_seconds: f64,
}

/// Inserts or updates run metadata in the runs table.
///
/// This should be called at the start of a run to record run-level information
/// like application version, fingerprints_source, fingerprints_version, and geoip_version.
pub async fn insert_run_metadata(
    pool: &SqlitePool,
    meta: &RunMetadata<'_>,
) -> Result<(), DatabaseError> {
    sqlx::query(
        "INSERT INTO runs (run_id, version, fingerprints_source, fingerprints_version, geoip_version, start_time_ms)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(run_id) DO UPDATE SET
             version=excluded.version,
             fingerprints_source=excluded.fingerprints_source,
             fingerprints_version=excluded.fingerprints_version,
             geoip_version=excluded.geoip_version,
             start_time_ms=excluded.start_time_ms",
    )
    .bind(meta.run_id)
    .bind(meta.version)
    .bind(meta.fingerprints_source)
    .bind(meta.fingerprints_version)
    .bind(meta.geoip_version)
    .bind(meta.start_time_ms)
    .execute(pool)
    .await
    .map_err(DatabaseError::SqlError)?;

    Ok(())
}

/// Updates run statistics when a run completes.
///
/// Stores all statistics from a ScanReport including elapsed time for easy querying.
pub async fn update_run_stats(
    pool: &SqlitePool,
    stats: &RunStats<'_>,
) -> Result<(), DatabaseError> {
    let end_time_ms = chrono::Utc::now().timestamp_millis();

    sqlx::query(
        "UPDATE runs
         SET end_time_ms = ?, total_urls = ?, successful_urls = ?, failed_urls = ?, elapsed_seconds = ?
         WHERE run_id = ?",
    )
    .bind(end_time_ms)
    .bind(stats.total_urls)
    .bind(stats.successful_urls)
    .bind(stats.failed_urls)
    .bind(stats.elapsed_seconds)
    .bind(stats.run_id)
    .execute(pool)
    .await
    .map_err(DatabaseError::SqlError)?;

    Ok(())
}

/// Query run history from the database.
///
/// Returns all completed runs sorted by start_time_ms (most recent first).
/// Useful for reviewing past scan results after closing the terminal.
///
/// # Example
///
/// ```no_run
/// use domain_status::query_run_history;
/// use sqlx::SqlitePool;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let pool = SqlitePool::connect("sqlite:./domain_status.db").await?;
/// let runs = query_run_history(&pool, Some(10)).await?;
/// for run in runs {
///     println!("Run {}: {} URLs ({} succeeded, {} failed) in {:.1}s",
///              run.run_id, run.total_urls, run.successful_urls,
///              run.failed_urls, run.elapsed_seconds.unwrap_or(0.0));
/// }
/// # Ok(())
/// # }
/// ```
pub async fn query_run_history(
    pool: &SqlitePool,
    limit: Option<usize>,
) -> Result<Vec<RunSummary>, DatabaseError> {
    let query = if let Some(limit) = limit {
        format!(
            "SELECT run_id, version, start_time_ms, end_time_ms, total_urls, successful_urls, failed_urls, elapsed_seconds
             FROM runs
             WHERE end_time_ms IS NOT NULL
             ORDER BY start_time_ms DESC
             LIMIT {}",
            limit
        )
    } else {
        "SELECT run_id, version, start_time_ms, end_time_ms, total_urls, successful_urls, failed_urls, elapsed_seconds
         FROM runs
         WHERE end_time_ms IS NOT NULL
         ORDER BY start_time_ms DESC"
            .to_string()
    };

    let rows = sqlx::query(&query)
        .fetch_all(pool)
        .await
        .map_err(DatabaseError::SqlError)?;

    let summaries: Vec<RunSummary> = rows
        .into_iter()
        .map(|row| RunSummary {
            run_id: row.get("run_id"),
            version: row.get("version"),
            start_time_ms: row.get("start_time_ms"),
            end_time_ms: row.get("end_time_ms"),
            total_urls: row.get("total_urls"),
            successful_urls: row.get("successful_urls"),
            failed_urls: row.get("failed_urls"),
            elapsed_seconds: row.get("elapsed_seconds"),
        })
        .collect();

    Ok(summaries)
}

/// Summary of a completed run, suitable for displaying run history.
#[derive(Debug, Clone)]
pub struct RunSummary {
    /// Unique identifier for this run (e.g., "run_1765150444953").
    pub run_id: String,
    /// Application version that ran this scan (e.g., "0.1.4").
    pub version: Option<String>,
    /// Start time as milliseconds since Unix epoch.
    pub start_time_ms: i64,
    /// End time as milliseconds since Unix epoch (None if run still in progress).
    pub end_time_ms: Option<i64>,
    /// Total number of URLs processed in this run.
    pub total_urls: i32,
    /// Number of URLs that were successfully processed.
    pub successful_urls: i32,
    /// Number of URLs that failed to process.
    pub failed_urls: i32,
    /// Total execution time in seconds (None if run still in progress).
    pub elapsed_seconds: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;

    use crate::storage::test_helpers::create_test_pool;

    #[tokio::test]
    async fn test_insert_run_metadata_basic() {
        let pool = create_test_pool().await;

        let meta = RunMetadata {
            run_id: "test-run-123",
            start_time_ms: 1704067200000, // 2024-01-01 00:00:00 UTC
            version: "0.1.4",
            fingerprints_source: Some("https://github.com/wappalyzer/wappalyzer"),
            fingerprints_version: Some("abc123def456"),
            geoip_version: Some("2024-01-01"),
        };
        let result = insert_run_metadata(&pool, &meta).await;

        assert!(result.is_ok());

        // Verify insertion
        let row = sqlx::query(
            "SELECT run_id, fingerprints_source, fingerprints_version, geoip_version, start_time_ms FROM runs WHERE run_id = ?",
        )
        .bind("test-run-123")
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch run metadata");

        assert_eq!(row.get::<String, _>("run_id"), "test-run-123");
        assert_eq!(
            row.get::<Option<String>, _>("fingerprints_source"),
            Some("https://github.com/wappalyzer/wappalyzer".to_string())
        );
        assert_eq!(
            row.get::<Option<String>, _>("fingerprints_version"),
            Some("abc123def456".to_string())
        );
        assert_eq!(
            row.get::<Option<String>, _>("geoip_version"),
            Some("2024-01-01".to_string())
        );
        assert_eq!(row.get::<i64, _>("start_time_ms"), 1704067200000);
    }

    #[tokio::test]
    async fn test_insert_run_metadata_with_none_values() {
        let pool = create_test_pool().await;

        let meta = RunMetadata {
            run_id: "test-run-456",
            start_time_ms: 1704067200000,
            version: "0.1.4",
            fingerprints_source: None,
            fingerprints_version: None,
            geoip_version: None,
        };
        let result = insert_run_metadata(&pool, &meta).await;

        assert!(result.is_ok());

        // Verify insertion with None values
        let row = sqlx::query(
            "SELECT version, fingerprints_source, fingerprints_version, geoip_version FROM runs WHERE run_id = ?",
        )
        .bind("test-run-456")
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch run metadata");

        assert_eq!(
            row.get::<Option<String>, _>("version"),
            Some("0.1.4".to_string())
        );
        assert_eq!(row.get::<Option<String>, _>("fingerprints_source"), None);
        assert_eq!(row.get::<Option<String>, _>("fingerprints_version"), None);
        assert_eq!(row.get::<Option<String>, _>("geoip_version"), None);
    }

    #[tokio::test]
    async fn test_insert_run_metadata_upsert() {
        let pool = create_test_pool().await;

        // Insert initial metadata
        let meta1 = RunMetadata {
            run_id: "test-run-789",
            start_time_ms: 1704067200000,
            version: "0.1.4",
            fingerprints_source: Some("https://github.com/wappalyzer/wappalyzer"),
            fingerprints_version: Some("abc123"),
            geoip_version: Some("2024-01-01"),
        };
        insert_run_metadata(&pool, &meta1)
            .await
            .expect("Failed to insert initial metadata");

        // Update with new values
        let meta2 = RunMetadata {
            run_id: "test-run-789",
            start_time_ms: 1704153600000, // New start time
            version: "0.1.5",             // Updated version
            fingerprints_source: Some("https://github.com/wappalyzer/wappalyzer"),
            fingerprints_version: Some("def456"), // Updated version
            geoip_version: Some("2024-01-02"),    // Updated GeoIP version
        };
        let result = insert_run_metadata(&pool, &meta2).await;

        assert!(result.is_ok());

        // Verify update
        let row = sqlx::query(
            "SELECT version, fingerprints_version, geoip_version, start_time_ms FROM runs WHERE run_id = ?",
        )
        .bind("test-run-789")
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch run metadata");

        assert_eq!(
            row.get::<Option<String>, _>("version"),
            Some("0.1.5".to_string())
        );
        assert_eq!(
            row.get::<Option<String>, _>("fingerprints_version"),
            Some("def456".to_string())
        );
        assert_eq!(
            row.get::<Option<String>, _>("geoip_version"),
            Some("2024-01-02".to_string())
        );
        assert_eq!(row.get::<i64, _>("start_time_ms"), 1704153600000);

        // Verify only one row exists (UPSERT, not INSERT)
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM runs WHERE run_id = ?")
            .bind("test-run-789")
            .fetch_one(&pool)
            .await
            .expect("Failed to count runs");

        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_update_run_stats_basic() {
        let pool = create_test_pool().await;

        // First insert run metadata
        let meta = RunMetadata {
            run_id: "test-run-stats",
            start_time_ms: 1704067200000,
            version: "0.1.4",
            fingerprints_source: Some("https://github.com/wappalyzer/wappalyzer"),
            fingerprints_version: Some("abc123"),
            geoip_version: None,
        };
        insert_run_metadata(&pool, &meta)
            .await
            .expect("Failed to insert run metadata");

        // Update run stats
        let stats = RunStats {
            run_id: "test-run-stats",
            total_urls: 100,
            successful_urls: 95,
            failed_urls: 5,
            elapsed_seconds: 10.5,
        };
        let result = update_run_stats(&pool, &stats).await;

        assert!(result.is_ok());

        // Verify update
        let row = sqlx::query(
            "SELECT end_time_ms, total_urls, successful_urls, failed_urls, elapsed_seconds FROM runs WHERE run_id = ?",
        )
        .bind("test-run-stats")
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch run stats");

        let end_time_ms: i64 = row.get("end_time_ms");
        assert!(end_time_ms > 0); // Should be set to current time
        assert_eq!(row.get::<i32, _>("total_urls"), 100);
        assert_eq!(row.get::<i32, _>("successful_urls"), 95);
        assert_eq!(row.get::<i32, _>("failed_urls"), 5);
        assert_eq!(row.get::<Option<f64>, _>("elapsed_seconds"), Some(10.5));
    }

    #[tokio::test]
    async fn test_update_run_stats_zero_values() {
        let pool = create_test_pool().await;

        // Insert run metadata
        let meta = RunMetadata {
            run_id: "test-run-zero",
            start_time_ms: 1704067200000,
            version: "0.1.4",
            fingerprints_source: None,
            fingerprints_version: None,
            geoip_version: None,
        };
        insert_run_metadata(&pool, &meta)
            .await
            .expect("Failed to insert run metadata");

        // Update with zero values
        let stats = RunStats {
            run_id: "test-run-zero",
            total_urls: 0,
            successful_urls: 0,
            failed_urls: 0,
            elapsed_seconds: 0.0,
        };
        let result = update_run_stats(&pool, &stats).await;

        assert!(result.is_ok());

        // Verify update
        let row = sqlx::query(
            "SELECT total_urls, successful_urls, failed_urls, elapsed_seconds FROM runs WHERE run_id = ?",
        )
        .bind("test-run-zero")
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch run stats");

        assert_eq!(row.get::<i32, _>("total_urls"), 0);
        assert_eq!(row.get::<i32, _>("successful_urls"), 0);
        assert_eq!(row.get::<i32, _>("failed_urls"), 0);
        assert_eq!(row.get::<Option<f64>, _>("elapsed_seconds"), Some(0.0));
    }

    #[tokio::test]
    async fn test_update_run_stats_nonexistent_run() {
        let pool = create_test_pool().await;

        // Try to update stats for non-existent run
        let stats = RunStats {
            run_id: "nonexistent-run",
            total_urls: 100,
            successful_urls: 95,
            failed_urls: 5,
            elapsed_seconds: 15.0,
        };
        let result = update_run_stats(&pool, &stats).await;

        // Should succeed but update 0 rows
        assert!(result.is_ok());

        // Verify no row was created
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM runs WHERE run_id = ?")
            .bind("nonexistent-run")
            .fetch_one(&pool)
            .await
            .expect("Failed to count runs");

        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_insert_and_update_run_complete_flow() {
        let pool = create_test_pool().await;

        // Step 1: Insert run metadata at start
        let meta = RunMetadata {
            run_id: "complete-run",
            start_time_ms: 1704067200000,
            version: "0.1.4",
            fingerprints_source: Some("https://github.com/wappalyzer/wappalyzer"),
            fingerprints_version: Some("abc123"),
            geoip_version: Some("2024-01-01"),
        };
        insert_run_metadata(&pool, &meta)
            .await
            .expect("Failed to insert run metadata");

        // Step 2: Update stats at end
        let stats = RunStats {
            run_id: "complete-run",
            total_urls: 50,
            successful_urls: 48,
            failed_urls: 2,
            elapsed_seconds: 25.3,
        };
        let result = update_run_stats(&pool, &stats).await;
        assert!(result.is_ok());

        // Verify complete record
        let row = sqlx::query(
            "SELECT run_id, version, fingerprints_source, fingerprints_version, geoip_version, start_time_ms, end_time_ms, total_urls, successful_urls, failed_urls, elapsed_seconds FROM runs WHERE run_id = ?",
        )
        .bind("complete-run")
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch complete run record");

        assert_eq!(row.get::<String, _>("run_id"), "complete-run");
        assert_eq!(
            row.get::<Option<String>, _>("version"),
            Some("0.1.4".to_string())
        );
        assert_eq!(
            row.get::<Option<String>, _>("fingerprints_source"),
            Some("https://github.com/wappalyzer/wappalyzer".to_string())
        );
        assert_eq!(row.get::<i64, _>("start_time_ms"), 1704067200000);
        let end_time_ms: i64 = row.get("end_time_ms");
        assert!(end_time_ms > 0);
        assert_eq!(row.get::<i32, _>("total_urls"), 50);
        assert_eq!(row.get::<i32, _>("successful_urls"), 48);
        assert_eq!(row.get::<i32, _>("failed_urls"), 2);
        assert_eq!(row.get::<Option<f64>, _>("elapsed_seconds"), Some(25.3));
    }

    #[tokio::test]
    async fn test_query_run_history_with_limit() {
        // Test that query_run_history respects the limit parameter
        // This is critical - prevents loading too many runs into memory
        let pool = create_test_pool().await;

        // Create multiple completed runs
        for i in 0..5 {
            let run_id = format!("test-run-limit-{}", i);
            let meta = RunMetadata {
                run_id: &run_id,
                start_time_ms: 1704067200000 + (i as i64 * 1000),
                version: "0.1.4",
                fingerprints_source: None,
                fingerprints_version: None,
                geoip_version: None,
            };
            insert_run_metadata(&pool, &meta)
                .await
                .expect("Failed to insert run metadata");
            let stats = RunStats {
                run_id: &run_id,
                total_urls: 10,
                successful_urls: 9,
                failed_urls: 1,
                elapsed_seconds: 5.0,
            };
            update_run_stats(&pool, &stats)
                .await
                .expect("Failed to update run stats");
        }

        // Query with limit of 3
        let result = query_run_history(&pool, Some(3)).await;
        assert!(result.is_ok());
        let runs = result.unwrap();
        assert_eq!(
            runs.len(),
            3,
            "Should return exactly 3 runs when limit is 3"
        );
    }

    #[tokio::test]
    async fn test_query_run_history_without_limit() {
        // Test that query_run_history returns all runs when limit is None
        // This is critical - ensures unlimited queries work correctly
        let pool = create_test_pool().await;

        // Create multiple completed runs
        for i in 0..5 {
            let run_id = format!("test-run-unlimited-{}", i);
            let meta = RunMetadata {
                run_id: &run_id,
                start_time_ms: 1704067200000 + (i as i64 * 1000),
                version: "0.1.4",
                fingerprints_source: None,
                fingerprints_version: None,
                geoip_version: None,
            };
            insert_run_metadata(&pool, &meta)
                .await
                .expect("Failed to insert run metadata");
            let stats = RunStats {
                run_id: &run_id,
                total_urls: 10,
                successful_urls: 9,
                failed_urls: 1,
                elapsed_seconds: 5.0,
            };
            update_run_stats(&pool, &stats)
                .await
                .expect("Failed to update run stats");
        }

        // Query without limit
        let result = query_run_history(&pool, None).await;
        assert!(result.is_ok());
        let runs = result.unwrap();
        assert_eq!(runs.len(), 5, "Should return all 5 runs when limit is None");
    }

    #[tokio::test]
    async fn test_query_run_history_empty_result() {
        // Test that query_run_history returns empty vector when no completed runs exist
        // This is critical - edge case handling prevents panics
        let pool = create_test_pool().await;

        // Create a run but don't complete it (no end_time_ms)
        let meta = RunMetadata {
            run_id: "test-run-incomplete",
            start_time_ms: 1704067200000,
            version: "0.1.4",
            fingerprints_source: None,
            fingerprints_version: None,
            geoip_version: None,
        };
        insert_run_metadata(&pool, &meta)
            .await
            .expect("Failed to insert run metadata");
        // Don't call update_run_stats - this keeps end_time_ms as NULL

        // Query should return empty (only completed runs are returned)
        let result = query_run_history(&pool, None).await;
        assert!(result.is_ok());
        let runs = result.unwrap();
        assert!(
            runs.is_empty(),
            "Should return empty vector when no completed runs exist"
        );
    }

    #[tokio::test]
    async fn test_query_run_history_sorted_by_start_time_desc() {
        // Test that query_run_history returns runs sorted by start_time_ms DESC (most recent first)
        // This is critical - ensures correct ordering for display
        let pool = create_test_pool().await;

        // Create runs with different start times
        let run_ids = ["run-1", "run-2", "run-3"];
        let start_times = [1704067200000, 1704067300000, 1704067400000]; // Increasing times

        for (run_id, start_time) in run_ids.iter().zip(start_times.iter()) {
            let meta = RunMetadata {
                run_id,
                start_time_ms: *start_time,
                version: "0.1.4",
                fingerprints_source: None,
                fingerprints_version: None,
                geoip_version: None,
            };
            insert_run_metadata(&pool, &meta)
                .await
                .expect("Failed to insert run metadata");
            let stats = RunStats {
                run_id,
                total_urls: 10,
                successful_urls: 9,
                failed_urls: 1,
                elapsed_seconds: 5.0,
            };
            update_run_stats(&pool, &stats)
                .await
                .expect("Failed to update run stats");
        }

        // Query should return runs in descending order (most recent first)
        let result = query_run_history(&pool, None).await;
        assert!(result.is_ok());
        let runs = result.unwrap();
        assert_eq!(runs.len(), 3);
        // Most recent should be first
        assert_eq!(runs[0].run_id, "run-3");
        assert_eq!(runs[0].start_time_ms, 1704067400000);
        // Oldest should be last
        assert_eq!(runs[2].run_id, "run-1");
        assert_eq!(runs[2].start_time_ms, 1704067200000);
    }
}
