//! Centralized log level filters for dependencies (Mullvad-style).
//!
//! Named constants and a single helper keep crate-level filtering policy in one place,
//! so all logger initialization paths use the same rules.

use env_logger::Builder;
use log::LevelFilter;

/// Crates that only show Error level (Warn and below are suppressed).
///
/// Used for parsers and low-level libs that are very noisy (e.g. html5ever, `hickory_proto`).
pub const ERROR_ONLY_CRATES: &[&str] = &["html5ever", "hickory_proto"];

/// Crates capped at Info (Debug/Trace suppressed).
///
/// HTTP, DB, and networking crates that can be useful at Info but too noisy at Debug.
pub const INFO_CRATES: &[&str] = &["sqlx", "reqwest", "hyper"];

/// Crates capped at Warn (Info and below suppressed).
pub const WARN_CRATES: &[&str] = &["selectors"];

/// Applies the centralized module filters to an `env_logger::Builder`.
///
/// Call this after `filter_level(app_level)` so the app's level is the baseline;
/// then dependency crates are limited by the constants above, and `domain_status`
/// uses `app_level`.
pub fn apply_silenced_crates(builder: &mut Builder, app_level: LevelFilter) {
    for crate_name in ERROR_ONLY_CRATES {
        builder.filter_module(crate_name, LevelFilter::Error);
    }
    for crate_name in INFO_CRATES {
        builder.filter_module(crate_name, LevelFilter::Info);
    }
    for crate_name in WARN_CRATES {
        builder.filter_module(crate_name, LevelFilter::Warn);
    }
    builder.filter_module("domain_status", app_level);
}
