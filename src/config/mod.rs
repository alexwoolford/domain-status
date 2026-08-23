//! Application configuration and constants.
//!
//! Library consumers typically need [`Config`] and related enums only.
//! Most timeouts/header name constants are crate-private implementation detail.

mod constants;
mod headers;
mod merge;
mod types;

// Crate-internal constants/headers (not part of the stable library surface).
pub(crate) use constants::*;
pub(crate) use headers::*;

// Small set kept public for tests/docs and Config defaults.
pub use constants::{DB_PATH, DEFAULT_USER_AGENT, WHOIS_TIMEOUT_SECS};

pub use merge::{apply_file_config, merge_file_and_cli, FileConfig};
pub use types::{
    log_level_filter, Config, ConfigValidationError, FailOn, LogFormat, LogLevel,
    ScanDependencyOverrides,
};
