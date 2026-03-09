//! Config construction: merge file+env key-value map with CLI-derived config.
//!
//! Precedence: CLI > env > config file > defaults. The CLI layer loads the
//! file+env map and passes it here so that config building and validation
//! stay in the config module.

use std::collections::HashMap;
use std::path::PathBuf;

use super::types::{Config, FailOn, LogFormat, LogLevel};

/// Parsers for string values from config file / env (case-insensitive).
fn parse_log_level(s: &str) -> Option<LogLevel> {
    match s.to_lowercase().as_str() {
        "error" => Some(LogLevel::Error),
        "warn" => Some(LogLevel::Warn),
        "info" => Some(LogLevel::Info),
        "debug" => Some(LogLevel::Debug),
        "trace" => Some(LogLevel::Trace),
        _ => None,
    }
}

fn parse_log_format(s: &str) -> Option<LogFormat> {
    match s.to_lowercase().as_str() {
        "plain" => Some(LogFormat::Plain),
        "json" => Some(LogFormat::Json),
        _ => None,
    }
}

fn parse_fail_on(s: &str) -> Option<FailOn> {
    match s.to_lowercase().as_str() {
        "never" => Some(FailOn::Never),
        "any_failure" | "anyfailure" => Some(FailOn::AnyFailure),
        "pct>" => Some(FailOn::PctGreaterThan),
        _ => None,
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.to_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Applies key-value config (from file + env) onto `Config`.
/// Only known keys are applied; invalid values are skipped.
pub fn apply_file_env_map_to_config(config: &mut Config, map: &HashMap<String, String>) {
    for (key, value) in map {
        let key_lower = key.to_lowercase();
        match key_lower.as_str() {
            "file" => config.file = PathBuf::from(value),
            "db_path" => config.db_path = PathBuf::from(value),
            "log_file" => config.log_file = Some(PathBuf::from(value)),
            "log_level" => {
                if let Some(lvl) = parse_log_level(value) {
                    config.log_level = lvl;
                }
            }
            "log_format" => {
                if let Some(fmt) = parse_log_format(value) {
                    config.log_format = fmt;
                }
            }
            "max_concurrency" => {
                if let Ok(n) = value.parse::<usize>() {
                    config.max_concurrency = n;
                }
            }
            "timeout_seconds" => {
                if let Ok(n) = value.parse::<u64>() {
                    config.timeout_seconds = n;
                }
            }
            "user_agent" => config.user_agent = value.clone(),
            "rate_limit_rps" => {
                if let Ok(n) = value.parse::<u32>() {
                    config.rate_limit_rps = n;
                }
            }
            "max_per_domain" => {
                if let Ok(n) = value.parse::<usize>() {
                    config.max_per_domain = n;
                }
            }
            "adaptive_error_threshold" => {
                if let Ok(n) = value.parse::<f64>() {
                    config.adaptive_error_threshold = n;
                }
            }
            "fingerprints" => config.fingerprints = Some(value.clone()),
            "geoip" => config.geoip = Some(value.clone()),
            "status_port" => {
                if let Ok(n) = value.parse::<u16>() {
                    config.status_port = Some(n);
                }
            }
            "enable_whois" => {
                config.enable_whois = parse_bool(value).unwrap_or(false);
            }
            "fail_on" => {
                if let Some(f) = parse_fail_on(value) {
                    config.fail_on = f;
                }
            }
            "fail_on_pct_threshold" => {
                if let Ok(n) = value.parse::<u8>() {
                    config.fail_on_pct_threshold = n;
                }
            }
            _ => {}
        }
    }
}

/// Builds `Config` with precedence: CLI > env > config file > defaults.
///
/// Call this from the CLI layer after loading the file+env map and converting
/// the scan command to `Config` via `Config::from(scan_cmd)`.
#[must_use]
pub fn merge_file_env_and_cli(
    file_env_map: Option<&HashMap<String, String>>,
    cli_config: Config,
) -> Config {
    let mut config = Config::default();
    if let Some(map) = file_env_map {
        apply_file_env_map_to_config(&mut config, map);
    }
    config.file = cli_config.file;
    config.log_level = cli_config.log_level;
    config.log_level_filter_override = cli_config.log_level_filter_override;
    config.log_format = cli_config.log_format;
    config.db_path = cli_config.db_path;
    config.max_concurrency = cli_config.max_concurrency;
    config.timeout_seconds = cli_config.timeout_seconds;
    config.user_agent = cli_config.user_agent;
    config.rate_limit_rps = cli_config.rate_limit_rps;
    config.max_per_domain = cli_config.max_per_domain;
    config.adaptive_error_threshold = cli_config.adaptive_error_threshold;
    config.fingerprints = cli_config.fingerprints;
    config.geoip = cli_config.geoip;
    config.status_port = cli_config.status_port;
    config.enable_whois = cli_config.enable_whois;
    config.fail_on = cli_config.fail_on;
    config.fail_on_pct_threshold = cli_config.fail_on_pct_threshold;
    config.log_file = cli_config.log_file;
    config.progress_callback = None;
    config.dependency_overrides = None;
    config
}
