// Shared test helpers for database setup and test data creation.
//
// This module provides common utilities used across multiple test files to reduce duplication.

use sqlx::{Row, SqlitePool};
use std::path::PathBuf;

use domain_status::run_migrations;

/// Creates a test database pool with migrations applied.
/// Uses an in-memory database for fast test execution.
#[allow(dead_code)] // Used by other test files
pub async fn create_test_pool() -> SqlitePool {
    let pool = SqlitePool::connect("sqlite::memory:")
        .await
        .expect("Failed to create test database pool");
    run_migrations(&pool)
        .await
        .expect("Failed to run migrations");
    pool
}

/// Creates a test database pool from a file path.
/// Useful for tests that need persistence or specific database files.
/// If the database file already exists, it will be reused (not truncated).
pub async fn create_test_pool_with_path(db_path: &PathBuf) -> SqlitePool {
    // Create the database file first (SQLite requires the file to exist or be created)
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).expect("Failed to create parent directory");
    }
    // Use OpenOptions to avoid truncating existing database files
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .read(true)
        .open(db_path)
        .expect("Failed to create/open database file");

    let db_path_str = db_path.to_string_lossy().to_string();
    let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", db_path_str))
        .await
        .expect("Failed to create test database");

    // Only run migrations if the database is new (check if url_status table exists)
    let table_exists: bool = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='url_status'",
    )
    .fetch_one(&pool)
    .await
    .map(|count: i64| count > 0)
    .unwrap_or(false);

    if !table_exists {
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");
    }

    pool
}

/// Creates a test URL status record and returns its ID.
/// Uses provided parameters for flexibility in tests.
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
            domain, final_domain, ip_address, status, status_description,
            response_time, title, timestamp, run_id, is_mobile_friendly
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

/// Creates a test URL status record with default values.
/// Convenience function for tests that don't need specific values.
#[allow(dead_code)] // Used by other test files
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

/// Creates a test run record and returns its run_id.
/// Uses direct SQL insertion for simplicity in tests.
#[allow(dead_code)] // Used by other test files
pub async fn create_test_run(pool: &SqlitePool, run_id: &str, timestamp: i64) -> String {
    sqlx::query("INSERT INTO runs (run_id, start_time, version, fingerprints_source, fingerprints_version, geoip_version) VALUES (?, ?, ?, ?, ?, ?)")
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
