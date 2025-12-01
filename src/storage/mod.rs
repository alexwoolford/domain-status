// storage/mod.rs
// Database operations module

pub mod batch;
pub mod circuit_breaker;
pub mod failure;
pub mod insert;
pub mod migrations;
pub mod models;
pub mod pool;

// Re-export commonly used items
pub use batch::{start_batch_writer, BatchConfig, BatchRecord};
pub use failure::record_url_failure;
pub use insert::insert_run_metadata;
pub use insert::update_run_stats;
pub use migrations::run_migrations;
pub use models::UrlRecord;
pub use pool::init_db_pool;

// Note: insert_geoip_data is used internally by fetch module, not exported here
