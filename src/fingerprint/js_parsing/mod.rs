//! JavaScript pattern parsing utilities (test-only; does NOT execute JavaScript).
//!
//! Quarantined under `#[cfg(test)]` — production fingerprinting matches static
//! HTML/script text and does not use this stripper.

mod utils;

pub use utils::strip_js_comments_and_strings;
