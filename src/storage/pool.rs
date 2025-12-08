//! Database connection pool management.
//!
//! This module initializes and configures the SQLite connection pool with:
//! - WAL mode enabled for concurrent access
//! - Connection limits and timeouts
//! - Automatic database file creation

use std::fs::OpenOptions;
use std::io::ErrorKind;
use std::sync::Arc;

use log::{error, info};
use sqlx::{Pool, Sqlite, SqlitePool};

use crate::config::DB_PATH;
use crate::error_handling::DatabaseError;

/// Initializes and returns a database connection pool.
///
/// Creates the database file if it doesn't exist and enables WAL mode
/// for better concurrent access.
///
/// Uses the `URL_CHECKER_DB_PATH` environment variable if set, otherwise falls back to the default.
///
/// Note: For library usage, prefer `init_db_pool_with_path` which accepts a path directly.
#[allow(dead_code)] // Kept for backward compatibility, but prefer init_db_pool_with_path
pub async fn init_db_pool() -> Result<Arc<Pool<Sqlite>>, DatabaseError> {
    let db_path = std::env::var("URL_CHECKER_DB_PATH").unwrap_or_else(|_| DB_PATH.to_string());
    init_db_pool_with_path(&std::path::PathBuf::from(&db_path)).await
}

/// Initializes and returns a database connection pool with an explicit path.
///
/// Creates the database file if it doesn't exist and enables WAL mode
/// for better concurrent access.
///
/// This version accepts a path directly, making it suitable for library usage
/// where configuration is passed explicitly rather than via environment variables.
pub async fn init_db_pool_with_path(
    db_path: &std::path::Path,
) -> Result<Arc<Pool<Sqlite>>, DatabaseError> {
    let db_path_str = db_path.to_string_lossy().to_string();
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&db_path_str)
    {
        Ok(_) => info!("Database file created successfully."),
        Err(ref e) if e.kind() == ErrorKind::AlreadyExists => {
            info!("Database file already exists.")
        }
        Err(e) => {
            error!("Failed to create database file: {e}");
            return Err(DatabaseError::FileCreationError(e.to_string()));
        }
    }

    let pool = SqlitePool::connect(&format!("sqlite:{}", db_path_str))
        .await
        .map_err(|e| {
            error!("Failed to connect to database: {e}");
            DatabaseError::SqlError(e)
        })?;

    // Enable WAL mode
    sqlx::query("PRAGMA journal_mode=WAL")
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("Failed to set WAL mode: {e}");
            DatabaseError::SqlError(e)
        })?;

    Ok(Arc::new(pool))
}
