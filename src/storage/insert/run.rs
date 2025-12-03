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
