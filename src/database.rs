// database.rs
// Backward compatibility module - re-exports from storage module
// This allows existing code to continue working while we migrate to the new structure

// Re-export everything for backward compatibility
pub use crate::storage::{
    init_db_pool, insert_run_metadata, insert_url_record, run_migrations, update_run_stats,
    UrlRecord,
};
