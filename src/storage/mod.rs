//! Database operations and storage management.
//!
//! This module provides:
//! - Database connection pool management
//! - Direct record insertion (no batching - records written immediately)
//! - Failure tracking and recording
//! - Database migrations
//! - Circuit breaker for write operations
//!
//! All database operations use SQLite with WAL mode enabled for concurrent access.

pub mod circuit_breaker;
pub mod failure;
pub mod insert;
pub mod migrations;
pub mod models;
pub mod pool;
pub mod record;

#[cfg(test)]
mod test_helpers;

// Re-export commonly used items
pub use failure::record_url_failure;
pub use insert::{insert_run_metadata, query_run_history, update_run_stats, RunSummary};
pub use migrations::run_migrations;
pub use models::UrlRecord;
pub use pool::{init_db_pool_with_path, DbPool};
pub use record::BatchRecord;

// Note: insert_geoip_data is used internally by fetch module, not exported here
