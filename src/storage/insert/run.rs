//! Run metadata insertion.
//!
//! This module handles inserting and updating run-level metadata and statistics.

use sqlx::{Row, SqlitePool};

use crate::error_handling::DatabaseError;

/// Inserts or updates run metadata in the runs table.
///
/// This should be called at the start of a run to record run-level information
/// like application version, fingerprints_source, fingerprints_version, and geoip_version.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `run_id` - Unique identifier for this run
/// * `start_time_ms` - Start time as milliseconds since Unix epoch
/// * `version` - Application version (e.g., "0.1.4") from Cargo.toml
/// * `fingerprints_source` - Source URL of the fingerprint ruleset
/// * `fingerprints_version` - Version/commit hash of the fingerprint ruleset
/// * `geoip_version` - Version/build date of the GeoIP database (None if GeoIP disabled)
pub async fn insert_run_metadata(
    pool: &SqlitePool,
    run_id: &str,
    start_time_ms: i64,
    version: &str,
    fingerprints_source: Option<&str>,
    fingerprints_version: Option<&str>,
    geoip_version: Option<&str>,
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
    .bind(run_id)
    .bind(version)
    .bind(fingerprints_source)
    .bind(fingerprints_version)
    .bind(geoip_version)
    .bind(start_time_ms)
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
    run_id: &str,
    total_urls: i32,
    successful_urls: i32,
    failed_urls: i32,
    elapsed_seconds: f64,
) -> Result<(), DatabaseError> {
    let end_time_ms = chrono::Utc::now().timestamp_millis();

    sqlx::query(
        "UPDATE runs
         SET end_time_ms = ?, total_urls = ?, successful_urls = ?, failed_urls = ?, elapsed_seconds = ?
         WHERE run_id = ?",
    )
    .bind(end_time_ms)
    .bind(total_urls)
    .bind(successful_urls)
    .bind(failed_urls)
    .bind(elapsed_seconds)
    .bind(run_id)
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

        let result = insert_run_metadata(
            &pool,
            "test-run-123",
            1704067200000, // 2024-01-01 00:00:00 UTC
            "0.1.4",
            Some("https://github.com/wappalyzer/wappalyzer"),
            Some("abc123def456"),
            Some("2024-01-01"),
        )
        .await;

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

        let result = insert_run_metadata(
            &pool,
            "test-run-456",
            1704067200000,
            "0.1.4",
            None,
            None,
            None,
        )
        .await;

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
        insert_run_metadata(
            &pool,
            "test-run-789",
            1704067200000,
            "0.1.4",
            Some("https://github.com/wappalyzer/wappalyzer"),
            Some("abc123"),
            Some("2024-01-01"),
        )
        .await
        .expect("Failed to insert initial metadata");

        // Update with new values
        let result = insert_run_metadata(
            &pool,
            "test-run-789",
            1704153600000, // New start time
            "0.1.5",       // Updated version
            Some("https://github.com/wappalyzer/wappalyzer"),
            Some("def456"),     // Updated version
            Some("2024-01-02"), // Updated GeoIP version
        )
        .await;

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
        insert_run_metadata(
            &pool,
            "test-run-stats",
            1704067200000,
            "0.1.4",
            Some("https://github.com/wappalyzer/wappalyzer"),
            Some("abc123"),
            None,
        )
        .await
        .expect("Failed to insert run metadata");

        // Update run stats
        let result = update_run_stats(&pool, "test-run-stats", 100, 95, 5, 10.5).await;

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
        insert_run_metadata(
            &pool,
            "test-run-zero",
            1704067200000,
            "0.1.4",
            None,
            None,
            None,
        )
        .await
        .expect("Failed to insert run metadata");

        // Update with zero values
        let result = update_run_stats(&pool, "test-run-zero", 0, 0, 0, 0.0).await;

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
        let result = update_run_stats(&pool, "nonexistent-run", 100, 95, 5, 15.0).await;

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
        insert_run_metadata(
            &pool,
            "complete-run",
            1704067200000,
            "0.1.4",
            Some("https://github.com/wappalyzer/wappalyzer"),
            Some("abc123"),
            Some("2024-01-01"),
        )
        .await
        .expect("Failed to insert run metadata");

        // Step 2: Update stats at end
        let result = update_run_stats(&pool, "complete-run", 50, 48, 2, 25.3).await;
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
}
