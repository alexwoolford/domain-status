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
#[allow(clippy::implicit_hasher)] // Internal function; always called with std HashMap, no need for generic hasher
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
            "user_agent" => config.user_agent.clone_from(value),
            "rate_limit_rps" => {
                if let Ok(n) = value.parse::<u32>() {
                    config.rate_limit_rps = n;
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
            "scan_external_scripts" => {
                config.scan_external_scripts = parse_bool(value).unwrap_or(false);
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
/// When `cli_explicit` is `Some(keys)`, only config fields whose name is in `keys` are
/// overwritten with `cli_config`; others keep file+env values. When `None`, every field
/// is overwritten (backward compatible). Use `Some` so file/env values are preserved
/// for options the user did not set on the CLI or via env.
///
/// Call this from the CLI layer after loading the file+env map and converting
/// the scan command to `Config` via `config_from_scan_command(scan_cmd)`.
#[must_use]
#[allow(clippy::implicit_hasher)] // Internal function; always called with std HashMap, no need for generic hasher
pub fn merge_file_env_and_cli(
    file_env_map: Option<&HashMap<String, String>>,
    cli_config: Config,
    cli_explicit: Option<&[&str]>,
) -> Config {
    let overwrite = |key: &str| -> bool { cli_explicit.is_none_or(|keys| keys.contains(&key)) };

    let mut config = Config::default();
    if let Some(map) = file_env_map {
        apply_file_env_map_to_config(&mut config, map);
    }

    if overwrite("file") {
        config.file = cli_config.file;
    }
    if overwrite("log_level") {
        config.log_level = cli_config.log_level;
    }
    if overwrite("log_level_filter_override") {
        config.log_level_filter_override = cli_config.log_level_filter_override;
    }
    if overwrite("log_format") {
        config.log_format = cli_config.log_format;
    }
    if overwrite("db_path") {
        config.db_path = cli_config.db_path;
    }
    if overwrite("max_concurrency") {
        config.max_concurrency = cli_config.max_concurrency;
    }
    if overwrite("timeout_seconds") {
        config.timeout_seconds = cli_config.timeout_seconds;
    }
    if overwrite("user_agent") {
        config.user_agent = cli_config.user_agent;
    }
    if overwrite("rate_limit_rps") {
        config.rate_limit_rps = cli_config.rate_limit_rps;
    }
    if overwrite("fingerprints") {
        config.fingerprints = cli_config.fingerprints;
    }
    if overwrite("geoip") {
        config.geoip = cli_config.geoip;
    }
    if overwrite("status_port") {
        config.status_port = cli_config.status_port;
    }
    if overwrite("enable_whois") {
        config.enable_whois = cli_config.enable_whois;
    }
    if overwrite("scan_external_scripts") {
        config.scan_external_scripts = cli_config.scan_external_scripts;
    }
    if overwrite("fail_on") {
        config.fail_on = cli_config.fail_on;
    }
    if overwrite("fail_on_pct_threshold") {
        config.fail_on_pct_threshold = cli_config.fail_on_pct_threshold;
    }
    if overwrite("log_file") {
        config.log_file = cli_config.log_file;
    }

    config.progress_callback = None;
    config.dependency_overrides = None;
    config.allow_localhost_for_tests = false; // Never enable from file/CLI; tests set in code only
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_preserves_file_env_when_cli_not_explicit() {
        let mut file_env = HashMap::new();
        file_env.insert("file".to_string(), "/path/to/urls.txt".to_string());
        file_env.insert("log_level".to_string(), "debug".to_string());
        file_env.insert("max_concurrency".to_string(), "100".to_string());

        let cli_config = Config {
            file: PathBuf::from("/cli/urls.txt"),
            log_level: LogLevel::Info,
            max_concurrency: 30,
            ..Default::default()
        };

        // Explicit empty: user set nothing, so file+env values are preserved
        let merged = merge_file_env_and_cli(Some(&file_env), cli_config.clone(), Some(&[]));
        assert!(
            matches!(merged.log_level, LogLevel::Debug),
            "file+env log_level preserved when not explicit"
        );
        assert_eq!(
            merged.max_concurrency, 100,
            "file+env max_concurrency preserved when not explicit"
        );

        // Only log_level explicitly set: only it is overwritten
        let merged2 =
            merge_file_env_and_cli(Some(&file_env), cli_config.clone(), Some(&["log_level"]));
        assert!(
            matches!(merged2.log_level, LogLevel::Info),
            "cli log_level overwrites when explicit"
        );
        assert_eq!(
            merged2.max_concurrency, 100,
            "file+env max_concurrency still preserved"
        );

        // None: backward compat, all overwritten
        let merged3 = merge_file_env_and_cli(Some(&file_env), cli_config, None);
        assert!(matches!(merged3.log_level, LogLevel::Info));
        assert_eq!(merged3.max_concurrency, 30);
    }
}
