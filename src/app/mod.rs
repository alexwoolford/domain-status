//! Main application modules.
//!
//! This module provides utilities for URL validation, logging, shutdown handling,
//! and statistics printing used by the main application.

pub mod logging;
pub mod shutdown;
pub mod statistics;
pub mod url;

// Re-export public API
pub use logging::log_progress;
pub use shutdown::shutdown_gracefully;
pub use statistics::{print_and_save_final_statistics, print_timing_statistics};
pub use url::validate_and_normalize_url;
