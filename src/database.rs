// database.rs
// Re-exports from storage module for convenience
pub use crate::storage::{
    init_db_pool, insert_run_metadata, run_migrations, update_run_stats, UrlRecord,
};
