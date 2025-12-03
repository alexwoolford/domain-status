//! Utility functions for URL processing.
//!
//! This module provides:
//! - URL processing orchestration with retry logic
//! - Error retriability determination
//! - String sanitization utilities
//! - CSS selector parsing utilities
//! - Timing metrics for performance analysis

mod process;
mod retry;
pub mod sanitize;
mod selector;
mod timing;

pub use process::{process_url, ProcessUrlResult};
pub use selector::{parse_selector_unsafe, parse_selector_with_fallback};
pub use timing::{TimingStats, UrlTimingMetrics, duration_to_ms};

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
