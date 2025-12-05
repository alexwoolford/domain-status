//! Run metadata insertion.
//!
//! This module handles inserting and updating run-level metadata and statistics.

use sqlx::SqlitePool;

use crate::error_handling::DatabaseError;

/// Inserts or updates run metadata in the runs table.
///
/// This should be called at the start of a run to record run-level information
/// like fingerprints_source, fingerprints_version, and geoip_version.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `run_id` - Unique identifier for this run
/// * `start_time` - Start time as milliseconds since Unix epoch
/// * `fingerprints_source` - Source URL of the fingerprint ruleset
/// * `fingerprints_version` - Version/commit hash of the fingerprint ruleset
/// * `geoip_version` - Version/build date of the GeoIP database (None if GeoIP disabled)
pub async fn insert_run_metadata(
    pool: &SqlitePool,
    run_id: &str,
    start_time: i64,
    fingerprints_source: Option<&str>,
    fingerprints_version: Option<&str>,
    geoip_version: Option<&str>,
) -> Result<(), DatabaseError> {
    sqlx::query(
        "INSERT INTO runs (run_id, fingerprints_source, fingerprints_version, geoip_version, start_time)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(run_id) DO UPDATE SET
             fingerprints_source=excluded.fingerprints_source,
             fingerprints_version=excluded.fingerprints_version,
             geoip_version=excluded.geoip_version,
             start_time=excluded.start_time",
    )
    .bind(run_id)
    .bind(fingerprints_source)
    .bind(fingerprints_version)
    .bind(geoip_version)
    .bind(start_time)
    .execute(pool)
    .await
    .map_err(DatabaseError::SqlError)?;

    Ok(())
}

/// Updates run statistics when a run completes.
#[allow(dead_code)]
pub async fn update_run_stats(
    pool: &SqlitePool,
    run_id: &str,
    total_urls: i32,
    successful_urls: i32,
    failed_urls: i32,
) -> Result<(), DatabaseError> {
    let end_time = chrono::Utc::now().timestamp_millis();

    sqlx::query(
        "UPDATE runs 
         SET end_time = ?, total_urls = ?, successful_urls = ?, failed_urls = ?
         WHERE run_id = ?",
    )
    .bind(end_time)
    .bind(total_urls)
    .bind(successful_urls)
    .bind(failed_urls)
    .bind(run_id)
    .execute(pool)
    .await
    .map_err(DatabaseError::SqlError)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::migrations::run_migrations;
    use sqlx::{Row, SqlitePool};

    async fn create_test_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");
        pool
    }

    #[tokio::test]
    async fn test_insert_run_metadata_basic() {
        let pool = create_test_pool().await;

        let result = insert_run_metadata(
            &pool,
            "test-run-123",
            1704067200000, // 2024-01-01 00:00:00 UTC
            Some("https://github.com/wappalyzer/wappalyzer"),
            Some("abc123def456"),
            Some("2024-01-01"),
        )
        .await;

        assert!(result.is_ok());

        // Verify insertion
        let row = sqlx::query(
            "SELECT run_id, fingerprints_source, fingerprints_version, geoip_version, start_time FROM runs WHERE run_id = ?",
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
        assert_eq!(row.get::<i64, _>("start_time"), 1704067200000);
    }

    #[tokio::test]
    async fn test_insert_run_metadata_with_none_values() {
        let pool = create_test_pool().await;

        let result =
            insert_run_metadata(&pool, "test-run-456", 1704067200000, None, None, None).await;

        assert!(result.is_ok());

        // Verify insertion with None values
        let row = sqlx::query(
            "SELECT fingerprints_source, fingerprints_version, geoip_version FROM runs WHERE run_id = ?",
        )
        .bind("test-run-456")
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch run metadata");

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
            Some("https://github.com/wappalyzer/wappalyzer"),
            Some("def456"),     // Updated version
            Some("2024-01-02"), // Updated GeoIP version
        )
        .await;

        assert!(result.is_ok());

        // Verify update
        let row = sqlx::query(
            "SELECT fingerprints_version, geoip_version, start_time FROM runs WHERE run_id = ?",
        )
        .bind("test-run-789")
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch run metadata");

        assert_eq!(
            row.get::<Option<String>, _>("fingerprints_version"),
            Some("def456".to_string())
        );
        assert_eq!(
            row.get::<Option<String>, _>("geoip_version"),
            Some("2024-01-02".to_string())
        );
        assert_eq!(row.get::<i64, _>("start_time"), 1704153600000);

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
            Some("https://github.com/wappalyzer/wappalyzer"),
            Some("abc123"),
            None,
        )
        .await
        .expect("Failed to insert run metadata");

        // Update run stats
        let result = update_run_stats(&pool, "test-run-stats", 100, 95, 5).await;

        assert!(result.is_ok());

        // Verify update
        let row = sqlx::query(
            "SELECT end_time, total_urls, successful_urls, failed_urls FROM runs WHERE run_id = ?",
        )
        .bind("test-run-stats")
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch run stats");

        let end_time: i64 = row.get("end_time");
        assert!(end_time > 0); // Should be set to current time
        assert_eq!(row.get::<i32, _>("total_urls"), 100);
        assert_eq!(row.get::<i32, _>("successful_urls"), 95);
        assert_eq!(row.get::<i32, _>("failed_urls"), 5);
    }

    #[tokio::test]
    async fn test_update_run_stats_zero_values() {
        let pool = create_test_pool().await;

        // Insert run metadata
        insert_run_metadata(&pool, "test-run-zero", 1704067200000, None, None, None)
            .await
            .expect("Failed to insert run metadata");

        // Update with zero values
        let result = update_run_stats(&pool, "test-run-zero", 0, 0, 0).await;

        assert!(result.is_ok());

        // Verify update
        let row = sqlx::query(
            "SELECT total_urls, successful_urls, failed_urls FROM runs WHERE run_id = ?",
        )
        .bind("test-run-zero")
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch run stats");

        assert_eq!(row.get::<i32, _>("total_urls"), 0);
        assert_eq!(row.get::<i32, _>("successful_urls"), 0);
        assert_eq!(row.get::<i32, _>("failed_urls"), 0);
    }

    #[tokio::test]
    async fn test_update_run_stats_nonexistent_run() {
        let pool = create_test_pool().await;

        // Try to update stats for non-existent run
        let result = update_run_stats(&pool, "nonexistent-run", 100, 95, 5).await;

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
            Some("https://github.com/wappalyzer/wappalyzer"),
            Some("abc123"),
            Some("2024-01-01"),
        )
        .await
        .expect("Failed to insert run metadata");

        // Step 2: Update stats at end
        let result = update_run_stats(&pool, "complete-run", 50, 48, 2).await;
        assert!(result.is_ok());

        // Verify complete record
        let row = sqlx::query(
            "SELECT run_id, fingerprints_source, fingerprints_version, geoip_version, start_time, end_time, total_urls, successful_urls, failed_urls FROM runs WHERE run_id = ?",
        )
        .bind("complete-run")
        .fetch_one(&pool)
        .await
        .expect("Failed to fetch complete run record");

        assert_eq!(row.get::<String, _>("run_id"), "complete-run");
        assert_eq!(
            row.get::<Option<String>, _>("fingerprints_source"),
            Some("https://github.com/wappalyzer/wappalyzer".to_string())
        );
        assert_eq!(row.get::<i64, _>("start_time"), 1704067200000);
        let end_time: i64 = row.get("end_time");
        assert!(end_time > 0);
        assert_eq!(row.get::<i32, _>("total_urls"), 50);
        assert_eq!(row.get::<i32, _>("successful_urls"), 48);
        assert_eq!(row.get::<i32, _>("failed_urls"), 2);
    }
}
