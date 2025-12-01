//! Database module re-exports.
//!
//! This module provides convenient re-exports from the `storage` module
//! for backward compatibility and cleaner imports.

pub use crate::storage::{
    init_db_pool, insert_run_metadata, run_migrations, update_run_stats, UrlRecord,
};
