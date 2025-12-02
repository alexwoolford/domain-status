//! Application configuration and constants.
//!
//! This module provides:
//! - Configuration constants (timeouts, limits, etc.)
//! - HTTP header name constants
//! - CLI option types and parsing

mod constants;
mod headers;
mod types;

// Re-export all constants
pub use constants::*;
pub use headers::*;
pub use types::{LogFormat, Opt};

