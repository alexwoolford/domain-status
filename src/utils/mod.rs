//! Utility functions for URL processing.
//!
//! This module provides:
//! - URL processing orchestration with retry logic
//! - Error retriability determination
//! - IO error context (path/message on file errors)
//! - String sanitization utilities
//! - CSS selector parsing utilities
//! - Timing metrics for performance analysis

mod io_context;
mod process;
mod retry;
pub mod sanitize;
mod selector;
mod timing;

#[allow(unused_imports)]
pub use io_context::{
    ensure_parent_dir_secure, print_io_error_hint_if_applicable, warn_if_world_readable,
    IoErrorContext, WrappedIoError,
};
pub use process::{process_url, ProcessUrlResult};
pub use selector::parse_selector_with_fallback;
pub use timing::{duration_to_us, TimingStats, UrlTimingMetrics};

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
