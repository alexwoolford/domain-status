//! Application configuration and constants.
//!
//! This module provides:
//! - Configuration constants (timeouts, limits, etc.)
//! - HTTP header name constants
//! - Configuration types (library-only, no CLI dependencies)

mod constants;
mod headers;
mod types;

// Re-export all constants
pub use constants::*;
pub use headers::*;
pub use types::{Config, ConfigValidationError, FailOn, LogFormat, LogLevel};
