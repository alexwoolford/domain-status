//! Database module re-exports.
//!
//! This module provides convenient re-exports from the `storage` module
//! for backward compatibility and cleaner imports.

#[allow(unused_imports)] // Re-exports used by test code in app::statistics
pub use crate::storage::{update_run_stats, RunStats, UrlRecord};
