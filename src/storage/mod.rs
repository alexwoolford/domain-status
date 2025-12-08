//! Database operations and storage management.
//!
//! This module provides:
//! - Database connection pool management
//! - Batch writing for efficient inserts
//! - Failure tracking and recording
//! - Database migrations
//! - Circuit breaker for write operations
//!
//! All database operations use SQLite with WAL mode enabled for concurrent access.

pub mod batch;
pub mod circuit_breaker;
pub mod failure;
pub mod insert;
pub mod migrations;
pub mod models;
pub mod pool;

// Re-export commonly used items
pub use batch::BatchRecord;
pub use failure::record_url_failure;
pub use insert::{insert_run_metadata, query_run_history, update_run_stats, RunSummary};
pub use migrations::run_migrations;
pub use models::UrlRecord;
pub use pool::init_db_pool_with_path;

// Note: insert_geoip_data is used internally by fetch module, not exported here
