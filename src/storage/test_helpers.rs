//! Shared test helpers for storage module tests.
//!
//! This module provides common utilities for database setup and test data creation
//! used across storage module tests.

#[cfg(test)]
use sqlx::{Row, SqlitePool};

#[cfg(test)]
use crate::storage::run_migrations;

/// Creates a test database pool with migrations applied.
/// Uses an in-memory database for fast test execution.
#[cfg(test)]
pub async fn create_test_pool() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:")
        .await
        .expect("Failed to create test database pool");
    run_migrations(&pool)
        .await
        .expect("Failed to run migrations");
    pool
}

/// Creates a test URL status record with default values.
/// Convenience function for tests that don't need specific values.
#[cfg(test)]
pub async fn create_test_url_status_default(pool: &SqlitePool) -> i64 {
    create_test_url_status(
        pool,
        "example.com",
        "example.com",
        200,
        None,
        1704067200000i64,
    )
    .await
}

/// Creates a test URL status record and returns its ID.
/// Uses provided parameters for flexibility in tests.
#[cfg(test)]
pub async fn create_test_url_status(
    pool: &SqlitePool,
    domain: &str,
    final_domain: &str,
    status: i64,
    run_id: Option<&str>,
    timestamp: i64,
) -> i64 {
    sqlx::query(
        "INSERT INTO url_status (
            initial_domain, final_domain, ip_address, http_status, http_status_text,
            response_time_seconds, title, observed_at_ms, run_id, is_mobile_friendly
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING id",
    )
    .bind(domain)
    .bind(final_domain)
    .bind("192.0.2.1")
    .bind(status)
    .bind("OK")
    .bind(1.5f64)
    .bind("Test Page")
    .bind(timestamp)
    .bind(run_id)
    .bind(true)
    .fetch_one(pool)
    .await
    .expect("Failed to insert test URL status")
    .get::<i64, _>(0)
}

/// Creates a test run record.
/// Uses direct SQL insertion for simplicity in tests.
#[cfg(test)]
pub async fn create_test_run(pool: &SqlitePool, run_id: &str, timestamp: i64) -> String {
    sqlx::query("INSERT INTO runs (run_id, start_time_ms, version, fingerprints_source, fingerprints_version, geoip_version) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(run_id)
        .bind(timestamp)
        .bind("0.1.6")
        .bind("test://fingerprints")
        .bind("1.0.0")
        .bind("1.0.0")
        .execute(pool)
        .await
        .expect("Failed to insert test run");
    run_id.to_string()
}
