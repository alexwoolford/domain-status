//! JavaScript execution for technology detection.
//!
//! This module handles executing JavaScript code to detect technology properties,
//! matching the behavior of the Golang Wappalyzer tool.
//!
//! **Security measures:**
//! - Memory limit: 10MB per JavaScript context
//! - Execution timeout: 1 second per property check
//! - Script size limits: 100KB per script, 500KB total
//! - Maximum external scripts: 10 per page (to prevent excessive fetching)

mod execution;
mod fetch;
mod utils;

// Re-export public API (these are crate-private, used internally by detection module)
pub(crate) use execution::check_js_properties_batch;
pub(crate) use execution::check_js_property_async;
pub(crate) use fetch::fetch_and_combine_scripts;

#[cfg(test)]
pub use utils::strip_js_comments_and_strings;
