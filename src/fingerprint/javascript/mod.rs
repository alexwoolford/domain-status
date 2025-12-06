//! JavaScript utility functions for technology detection.
//!
//! **Note:** WappalyzerGo does NOT execute JavaScript and does NOT fetch external scripts.
//! It only analyzes the initial HTML response. We match this behavior:
//! - Script source patterns match against URLs from HTML (not fetched content)
//! - JS property matching is disabled - we only match via script tag IDs
//! - Only inline script content is used for JS pattern matching (if enabled)

mod utils;

#[cfg(test)]
pub use utils::strip_js_comments_and_strings;
