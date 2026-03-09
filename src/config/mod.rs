//! Application configuration and constants.
//!
//! This module provides:
//! - Configuration constants (timeouts, limits, etc.)
//! - HTTP header name constants
//! - Configuration types (library-only, no CLI dependencies)
//! - Config construction (merge file+env with CLI overlay)

mod constants;
mod headers;
mod merge;
mod types;

// Re-export all constants
pub use constants::*;
pub use headers::*;
pub use merge::{apply_file_env_map_to_config, merge_file_env_and_cli};
pub use types::{
    Config, ConfigValidationError, FailOn, LogFormat, LogLevel, ScanDependencyOverrides,
};
