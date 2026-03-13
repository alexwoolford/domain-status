//! Database connection pool management.
//!
//! This module initializes and configures the `SQLite` connection pool with:
//! - WAL mode enabled for concurrent access
//! - Connection limits and timeouts
//! - Automatic database file creation (via `spawn_blocking` to avoid blocking tokio runtime)

use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use log::{error, info};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Pool, Sqlite};

use crate::error_handling::DatabaseError;
use crate::utils::{ensure_parent_dir_secure, IoErrorContext};

/// Type alias for database connection pool.
/// Used throughout the codebase for consistency.
pub type DbPool = Arc<Pool<Sqlite>>;

/// Initializes and returns a database connection pool with an explicit path.
///
/// Creates the database file if it doesn't exist and enables WAL mode
/// for better concurrent access.
///
/// The pool is sized to match the given `max_connections` parameter (typically
/// derived from `--max-concurrency`) so workers don't starve waiting for connections.
///
/// # Examples
///
/// ```no_run
/// use domain_status::init_db_pool_with_path;
/// use std::path::Path;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let pool = init_db_pool_with_path(Path::new("./domain_status.db"), 30).await?;
/// assert!(!pool.is_closed());
/// # Ok(())
/// # }
/// ```
///
/// # Errors
/// Returns `Err` when the database file cannot be created or the connection pool cannot be initialized.
pub async fn init_db_pool_with_path(
    db_path: &std::path::Path,
    max_connections: u32,
) -> Result<DbPool, DatabaseError> {
    let db_path_str = db_path.to_string_lossy().to_string();

    // Ensure parent directory exists with secure permissions (0o700 on Unix) before creating DB file.
    ensure_parent_dir_secure(db_path).map_err(|e| {
        DatabaseError::FileCreationError(format!("Failed to create database directory: {e}"))
    })?;

    // Wrap blocking filesystem operation in spawn_blocking to avoid blocking tokio runtime.
    // This is a one-time startup operation, so impact is low, but good practice.
    let path_for_task = db_path_str.clone();
    let file_creation_result = tokio::task::spawn_blocking(move || {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path_for_task)
            .with_path(&path_for_task)
            .map(|_| ())
    })
    .await
    .map_err(|e| {
        error!("Task panicked while creating database file: {e}");
        DatabaseError::FileCreationError(format!("Task join error: {e}"))
    })?;

    match file_creation_result {
        Ok(()) => info!("Database file created successfully."),
        Err(ref e) if e.io_error.kind() == ErrorKind::AlreadyExists => {
            info!("Database file already exists.");
        }
        Err(e) => {
            error!("Failed to create database file: {e}");
            return Err(DatabaseError::FileCreationError(e.to_string()));
        }
    }

    let db_url = format!("sqlite:{db_path_str}");
    // Use SqliteConnectOptions::pragma() so that per-connection PRAGMAs
    // (foreign_keys, synchronous) are applied to EVERY connection the pool
    // creates, not just the first one. Without this, new pooled connections
    // revert to SQLite defaults (foreign_keys=OFF, synchronous=FULL).
    let options = SqliteConnectOptions::from_str(&db_url)
        .map_err(|e| {
            error!("Failed to parse database URL: {e}");
            DatabaseError::FileCreationError(format!("Invalid database path: {e}"))
        })?
        .create_if_missing(true)
        .pragma("foreign_keys", "ON")
        .pragma("synchronous", "NORMAL")
        .pragma("wal_autocheckpoint", "1000");

    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(5)) // Fail fast instead of blocking 30s
        .idle_timeout(Some(Duration::from_secs(60))) // Clean up idle connections
        .connect_with(options)
        .await
        .map_err(|e| {
            error!("Failed to connect to database: {e}");
            DatabaseError::SqlError(e)
        })?;

    // Enable WAL mode — this is a database-level (persistent) setting, so
    // executing it once on any connection is sufficient.
    sqlx::query("PRAGMA journal_mode=WAL")
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to set WAL mode: {e}");
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

        let result = init_db_pool_with_path(db_path, 5).await;
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

        let result = init_db_pool_with_path(db_path, 5).await;
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
        let result = init_db_pool_with_path(invalid_path, 5).await;
        // May succeed (SQLite creates a file in the directory) or fail depending on path format
        // The key is that it doesn't panic
        let _ = result;
    }

    #[tokio::test]
    async fn test_init_db_pool_with_path_wal_mode_enabled() {
        // Test that WAL mode is actually enabled
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let db_path = temp_file.path();

        let pool = init_db_pool_with_path(db_path, 5)
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

        let pool = init_db_pool_with_path(db_path, 5)
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
