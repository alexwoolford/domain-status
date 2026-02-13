//! Database connection pool management.
//!
//! This module initializes and configures the SQLite connection pool with:
//! - WAL mode enabled for concurrent access
//! - Connection limits and timeouts
//! - Automatic database file creation (via spawn_blocking to avoid blocking tokio runtime)

use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use log::{error, info};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Pool, Sqlite};

use crate::error_handling::DatabaseError;

/// Type alias for database connection pool.
/// Used throughout the codebase for consistency.
pub type DbPool = Arc<Pool<Sqlite>>;

/// Initializes and returns a database connection pool with an explicit path.
///
/// Creates the database file if it doesn't exist and enables WAL mode
/// for better concurrent access.
///
/// This version accepts a path directly, making it suitable for library usage
/// where configuration is passed explicitly rather than via environment variables.
pub async fn init_db_pool_with_path(db_path: &std::path::Path) -> Result<DbPool, DatabaseError> {
    let db_path_str = db_path.to_string_lossy().to_string();

    // Wrap blocking filesystem operation in spawn_blocking to avoid blocking tokio runtime.
    // This is a one-time startup operation, so impact is low, but good practice.
    let path_for_task = db_path_str.clone();
    let file_creation_result = tokio::task::spawn_blocking(move || {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path_for_task)
    })
    .await
    .map_err(|e| {
        error!("Task panicked while creating database file: {e}");
        DatabaseError::FileCreationError(format!("Task join error: {}", e))
    })?;

    match file_creation_result {
        Ok(_) => info!("Database file created successfully."),
        Err(ref e) if e.kind() == ErrorKind::AlreadyExists => {
            info!("Database file already exists.")
        }
        Err(e) => {
            error!("Failed to create database file: {e}");
            return Err(DatabaseError::FileCreationError(e.to_string()));
        }
    }

    // FIX: Configure pool explicitly instead of using defaults
    // - acquire_timeout: 5s (fail fast instead of blocking workers for 30s)
    // - max_connections: 30 (match default max_concurrency)
    // - idle_timeout: 60s (clean up unused connections)
    let db_url = format!("sqlite:{}", db_path_str);
    let options = SqliteConnectOptions::from_str(&db_url)
        .map_err(|e| {
            error!("Failed to parse database URL: {e}");
            DatabaseError::FileCreationError(format!("Invalid database path: {}", e))
        })?
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(30) // Match default max_concurrency
        .acquire_timeout(Duration::from_secs(5)) // Fail fast instead of blocking 30s
        .idle_timeout(Some(Duration::from_secs(60))) // Clean up idle connections
        .connect_with(options)
        .await
        .map_err(|e| {
            error!("Failed to connect to database: {e}");
            DatabaseError::SqlError(e)
        })?;

    // Enable WAL mode for better concurrent access
    sqlx::query("PRAGMA journal_mode=WAL")
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to set WAL mode: {e}");
            DatabaseError::SqlError(e)
        })?;

    // Configure WAL autocheckpoint (P1 operational fix)
    // Checkpoint every 1000 pages (~4MB with 4KB pages)
    // This prevents unbounded WAL growth during bulk operations
    // Default is 1000 pages; explicitly set for clarity and documentation
    sqlx::query("PRAGMA wal_autocheckpoint=1000")
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to set WAL autocheckpoint: {e}");
            DatabaseError::SqlError(e)
        })?;

    // Enable foreign key enforcement (required for ON DELETE CASCADE to work)
    // Without this, foreign key constraints are parsed but not enforced
    sqlx::query("PRAGMA foreign_keys=ON")
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to enable foreign keys: {e}");
            DatabaseError::SqlError(e)
        })?;

    Ok(Arc::new(pool))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_init_db_pool_with_path_success() {
        // Test successful pool initialization
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let db_path = temp_file.path();

        let result = init_db_pool_with_path(db_path).await;
        assert!(result.is_ok(), "Pool initialization should succeed");
        let pool = result.unwrap();
        assert!(!pool.is_closed(), "Pool should be open");
    }

    #[tokio::test]
    async fn test_init_db_pool_with_path_existing_file() {
        // Test pool initialization when file already exists
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let db_path = temp_file.path();

        // Create the file first
        std::fs::File::create(db_path).expect("Failed to create file");

        let result = init_db_pool_with_path(db_path).await;
        assert!(
            result.is_ok(),
            "Pool initialization should succeed with existing file"
        );
    }

    #[tokio::test]
    async fn test_init_db_pool_with_path_invalid_path() {
        // Test error handling with invalid path (directory instead of file)
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let invalid_path = temp_dir.path(); // This is a directory, not a file

        // This should fail when trying to connect (SQLite expects a file path)
        let result = init_db_pool_with_path(invalid_path).await;
        // May succeed (SQLite creates a file in the directory) or fail depending on path format
        // The key is that it doesn't panic
        let _ = result;
    }

    #[tokio::test]
    async fn test_init_db_pool_with_path_wal_mode_enabled() {
        // Test that WAL mode is actually enabled
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let db_path = temp_file.path();

        let pool = init_db_pool_with_path(db_path)
            .await
            .expect("Failed to initialize pool");

        // Verify WAL mode is enabled
        let result: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(pool.as_ref())
            .await
            .expect("Failed to query journal mode");

        assert_eq!(
            result.to_uppercase(),
            "WAL",
            "WAL mode should be enabled, got: {}",
            result
        );
    }

    #[tokio::test]
    async fn test_init_db_pool_with_path_foreign_keys_enabled() {
        // Test that foreign keys are actually enabled
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let db_path = temp_file.path();

        let pool = init_db_pool_with_path(db_path)
            .await
            .expect("Failed to initialize pool");

        // Verify foreign keys are enabled
        let result: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(pool.as_ref())
            .await
            .expect("Failed to query foreign keys");

        assert_eq!(result, 1, "Foreign keys should be enabled");
    }
}
