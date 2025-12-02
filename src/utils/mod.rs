//! Utility functions for URL processing.
//!
//! This module provides:
//! - URL processing orchestration with retry logic
//! - Error retriability determination
//! - String sanitization utilities
//! - CSS selector parsing utilities

mod process;
mod retry;
mod selector;
pub mod sanitize;

pub use process::{process_url, ProcessUrlResult};
pub use selector::{parse_selector_unsafe, parse_selector_with_fallback};

#[cfg(test)]
mod tests {
    include!("tests.rs");
}

