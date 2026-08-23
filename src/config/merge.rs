//! Config construction: merge typed file+env config with CLI-derived config.
//!
//! Precedence: CLI > env > config file > defaults. The CLI layer loads
//! [`FileConfig`] and passes it here so that config building and validation
//! stay in the config module.

use std::fmt;
use std::path::PathBuf;

use serde::de::{self, Deserializer, Visitor};
use serde::Deserialize;

use super::types::{Config, FailOn, LogFormat, LogLevel};

/// File / env overlay for scan settings.
///
/// All fields are `Option` so absent keys leave [`Config`] defaults in place.
/// Deserialized from TOML and `DOMAIN_STATUS_*` via the `config` crate.
/// Invalid enum/bool values fail deserialization (no silent skip).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct FileConfig {
    /// URL list path (library / non-CLI embeds; CLI uses the positional arg).
    pub file: Option<PathBuf>,
    /// Baseline log level.
    #[serde(default, deserialize_with = "deserialize_option_log_level")]
    pub log_level: Option<LogLevel>,
    /// Scan log file format.
    #[serde(default, deserialize_with = "deserialize_option_log_format")]
    pub log_format: Option<LogFormat>,
    /// `SQLite` database path.
    pub db_path: Option<PathBuf>,
    /// Maximum concurrent requests.
    pub max_concurrency: Option<usize>,
    /// Per-request HTTP timeout in seconds.
    pub timeout_seconds: Option<u64>,
    /// HTTP User-Agent.
    pub user_agent: Option<String>,
    /// Requests-per-second cap (`0` disables).
    pub rate_limit_rps: Option<u32>,
    /// Fingerprints URL or local path.
    pub fingerprints: Option<String>,
    /// `GeoIP` database path or download URL.
    pub geoip: Option<String>,
    /// Optional status HTTP server port.
    pub status_port: Option<u16>,
    /// Enable WHOIS/RDAP lookups.
    #[serde(default, deserialize_with = "deserialize_option_bool")]
    pub enable_whois: Option<bool>,
    /// Shared cache root.
    pub cache_dir: Option<PathBuf>,
    /// Fetch first-party external scripts for analysis.
    #[serde(default, deserialize_with = "deserialize_option_bool")]
    pub scan_external_scripts: Option<bool>,
    /// Exit-code failure policy.
    #[serde(default, deserialize_with = "deserialize_option_fail_on")]
    pub fail_on: Option<FailOn>,
    /// Failure % threshold when `fail_on` is `pct>`.
    pub fail_on_pct_threshold: Option<u8>,
    /// Scan log file path.
    pub log_file: Option<PathBuf>,
    /// Drain timeout after the input queue is empty (seconds).
    pub drain_timeout_secs: Option<u64>,
}

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
        "any-failure" | "any_failure" | "anyfailure" => Some(FailOn::AnyFailure),
        "pct>" => Some(FailOn::PctGreaterThan),
        _ => None,
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.trim().to_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn deserialize_option_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OptBoolVisitor;

    impl<'de> Visitor<'de> for OptBoolVisitor {
        type Value = Option<bool>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a boolean or bool-like string (true/false, 1/0, yes/no, on/off)")
        }

        fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
            Ok(Some(v))
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            parse_bool(v)
                .map(Some)
                .ok_or_else(|| E::custom(format!("invalid boolean value: {v:?}")))
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            self.visit_str(&v)
        }

        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
            match v {
                0 => Ok(Some(false)),
                1 => Ok(Some(true)),
                _ => Err(E::custom(format!("invalid boolean integer: {v}"))),
            }
        }

        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
            match v {
                0 => Ok(Some(false)),
                1 => Ok(Some(true)),
                _ => Err(E::custom(format!("invalid boolean integer: {v}"))),
            }
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D2: Deserializer<'de>>(
            self,
            deserializer: D2,
        ) -> Result<Self::Value, D2::Error> {
            deserializer.deserialize_any(OptBoolVisitor)
        }
    }

    deserializer.deserialize_any(OptBoolVisitor)
}

fn deserialize_option_fail_on<'de, D>(deserializer: D) -> Result<Option<FailOn>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OptFailOnVisitor;

    impl<'de> Visitor<'de> for OptFailOnVisitor {
        type Value = Option<FailOn>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("fail_on: never | any-failure | any_failure | pct>")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            parse_fail_on(v)
                .map(Some)
                .ok_or_else(|| E::custom(format!("invalid fail_on value: {v:?}")))
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            self.visit_str(&v)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D2: Deserializer<'de>>(
            self,
            deserializer: D2,
        ) -> Result<Self::Value, D2::Error> {
            deserializer.deserialize_any(OptFailOnVisitor)
        }
    }

    deserializer.deserialize_any(OptFailOnVisitor)
}

fn deserialize_option_log_level<'de, D>(deserializer: D) -> Result<Option<LogLevel>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OptLogLevelVisitor;

    impl<'de> Visitor<'de> for OptLogLevelVisitor {
        type Value = Option<LogLevel>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("log_level: error | warn | info | debug | trace")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            parse_log_level(v)
                .map(Some)
                .ok_or_else(|| E::custom(format!("invalid log_level value: {v:?}")))
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            self.visit_str(&v)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D2: Deserializer<'de>>(
            self,
            deserializer: D2,
        ) -> Result<Self::Value, D2::Error> {
            deserializer.deserialize_any(OptLogLevelVisitor)
        }
    }

    deserializer.deserialize_any(OptLogLevelVisitor)
}

fn deserialize_option_log_format<'de, D>(deserializer: D) -> Result<Option<LogFormat>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OptLogFormatVisitor;

    impl<'de> Visitor<'de> for OptLogFormatVisitor {
        type Value = Option<LogFormat>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("log_format: plain | json")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            parse_log_format(v)
                .map(Some)
                .ok_or_else(|| E::custom(format!("invalid log_format value: {v:?}")))
        }

        fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
            self.visit_str(&v)
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D2: Deserializer<'de>>(
            self,
            deserializer: D2,
        ) -> Result<Self::Value, D2::Error> {
            deserializer.deserialize_any(OptLogFormatVisitor)
        }
    }

    deserializer.deserialize_any(OptLogFormatVisitor)
}

/// Applies a typed file/env overlay onto `Config` (only `Some` fields).
pub fn apply_file_config(config: &mut Config, file: &FileConfig) {
    if let Some(ref path) = file.file {
        config.file.clone_from(path);
    }
    if let Some(ref path) = file.db_path {
        config.db_path.clone_from(path);
    }
    if let Some(ref path) = file.log_file {
        config.log_file = Some(path.clone());
    }
    if let Some(ref lvl) = file.log_level {
        config.log_level = lvl.clone();
    }
    if let Some(fmt) = file.log_format {
        config.log_format = fmt;
    }
    if let Some(n) = file.max_concurrency {
        config.max_concurrency = n;
    }
    if let Some(n) = file.timeout_seconds {
        config.timeout_seconds = n;
    }
    if let Some(n) = file.drain_timeout_secs {
        config.drain_timeout_secs = n;
    }
    if let Some(ref ua) = file.user_agent {
        config.user_agent.clone_from(ua);
    }
    if let Some(n) = file.rate_limit_rps {
        config.rate_limit_rps = n;
    }
    if let Some(ref fp) = file.fingerprints {
        config.fingerprints = Some(fp.clone());
    }
    if let Some(ref geo) = file.geoip {
        config.geoip = Some(geo.clone());
    }
    if let Some(n) = file.status_port {
        config.status_port = Some(n);
    }
    if let Some(b) = file.enable_whois {
        config.enable_whois = b;
    }
    if let Some(ref path) = file.cache_dir {
        config.cache_dir = Some(path.clone());
    }
    if let Some(b) = file.scan_external_scripts {
        config.scan_external_scripts = b;
    }
    if let Some(ref f) = file.fail_on {
        config.fail_on = f.clone();
    }
    if let Some(n) = file.fail_on_pct_threshold {
        config.fail_on_pct_threshold = n;
    }
}

/// Builds `Config` with precedence: CLI > env > config file > defaults.
///
/// When `cli_explicit` is `Some(keys)`, only config fields whose name is in `keys` are
/// overwritten with `cli_config`; others keep file+env values. When `None`, every field
/// is overwritten (backward compatible). Use `Some` so file/env values are preserved
/// for options the user did not set on the CLI or via env.
///
/// Call this from the CLI layer after loading [`FileConfig`] and converting
/// the scan command to `Config` via `config_from_scan_command(scan_cmd)`.
#[must_use]
pub fn merge_file_env_and_cli(
    file_env: Option<&FileConfig>,
    cli_config: Config,
    cli_explicit: Option<&[&str]>,
) -> Config {
    let overwrite = |key: &str| -> bool { cli_explicit.is_none_or(|keys| keys.contains(&key)) };

    let mut config = Config::default();
    if let Some(file) = file_env {
        apply_file_config(&mut config, file);
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
    // `--no-whois` wins over TOML enable_whois=true when set on the CLI.
    if overwrite("no_whois") {
        config.enable_whois = false;
    }
    if overwrite("cache_dir") {
        config.cache_dir = cli_config.cache_dir;
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
    if overwrite("drain_timeout_secs") {
        config.drain_timeout_secs = cli_config.drain_timeout_secs;
    }

    config.progress_callback = None;
    config.dependency_overrides = None;
    config.allow_localhost_for_tests = false; // Never enable from file/CLI; tests set in code only
    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn file_config_from_json(value: serde_json::Value) -> Result<FileConfig, serde_json::Error> {
        serde_json::from_value(value)
    }

    #[test]
    fn test_merge_preserves_file_env_when_cli_not_explicit() {
        let file_env = FileConfig {
            file: Some(PathBuf::from("/path/to/urls.txt")),
            log_level: Some(LogLevel::Debug),
            max_concurrency: Some(100),
            ..Default::default()
        };

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

    #[test]
    fn test_merge_applies_explicit_drain_timeout_secs() {
        let file_env = FileConfig {
            drain_timeout_secs: Some(45),
            ..Default::default()
        };

        let cli_config = Config {
            drain_timeout_secs: 90,
            ..Default::default()
        };

        // Not explicit: file/env value wins
        let merged = merge_file_env_and_cli(Some(&file_env), cli_config.clone(), Some(&[]));
        assert_eq!(merged.drain_timeout_secs, 45);

        // Explicit CLI flag wins
        let merged2 =
            merge_file_env_and_cli(Some(&file_env), cli_config, Some(&["drain_timeout_secs"]));
        assert_eq!(merged2.drain_timeout_secs, 90);
    }

    #[test]
    fn test_merge_fail_on_invalid_rejected_valid_applied_cli_overrides() {
        // Invalid fail_on fails deserialization (no silent skip)
        let err = file_config_from_json(json!({"fail_on": "boom"})).unwrap_err();
        assert!(
            err.to_string().contains("fail_on") || err.to_string().contains("boom"),
            "invalid fail_on must fail deserialize, got: {err}"
        );

        // Valid file value applied when CLI not explicit
        let valid = FileConfig {
            fail_on: Some(FailOn::PctGreaterThan),
            ..Default::default()
        };
        let merged_valid = merge_file_env_and_cli(
            Some(&valid),
            Config {
                fail_on: FailOn::Never,
                ..Default::default()
            },
            Some(&[]),
        );
        assert!(
            matches!(merged_valid.fail_on, FailOn::PctGreaterThan),
            "valid file fail_on=pct> must apply"
        );

        // Explicit CLI any_failure overrides file pct>
        let merged_cli = merge_file_env_and_cli(
            Some(&valid),
            Config {
                fail_on: FailOn::AnyFailure,
                ..Default::default()
            },
            Some(&["fail_on"]),
        );
        assert!(
            matches!(merged_cli.fail_on, FailOn::AnyFailure),
            "explicit CLI fail_on must override file"
        );

        // Invalid bool for enable_whois fails deserialization
        let bool_err = file_config_from_json(json!({"enable_whois": "maybe"})).unwrap_err();
        assert!(
            bool_err.to_string().contains("bool") || bool_err.to_string().contains("maybe"),
            "invalid enable_whois must fail deserialize, got: {bool_err}"
        );

        // CLI-style any-failure must parse from env/TOML
        let any_failure = file_config_from_json(json!({"fail_on": "any-failure"})).unwrap();
        let merged_any = merge_file_env_and_cli(
            Some(&any_failure),
            Config {
                fail_on: FailOn::Never,
                ..Default::default()
            },
            Some(&[]),
        );
        assert!(
            matches!(merged_any.fail_on, FailOn::AnyFailure),
            "fail_on=any-failure must apply from file/env"
        );
    }

    #[test]
    fn test_invalid_bool_deserialize_fails_instead_of_forcing_false() {
        // Previously silent skip could leave stale true; invalid values must error.
        let err = file_config_from_json(json!({
            "enable_whois": "maybe",
            "scan_external_scripts": " nah "
        }))
        .unwrap_err();
        assert!(
            err.to_string().contains("bool")
                || err.to_string().contains("maybe")
                || err.to_string().contains("nah"),
            "invalid bools must fail deserialize, got: {err}"
        );
        assert!(parse_bool("maybe").is_none());
        assert!(parse_bool(" nah ").is_none());
    }

    /// Adversarial: `--no-whois` on the CLI must beat `enable_whois=true` from the config
    /// file, even though `no_whois` and `enable_whois` are different keys under the hood.
    #[test]
    fn test_no_whois_cli_flag_overrides_toml_enable_whois_true() {
        let file_env = FileConfig {
            enable_whois: Some(true),
            ..Default::default()
        };

        // `--no-whois` set: explicit key list includes "no_whois" (not "enable_whois").
        let merged = merge_file_env_and_cli(
            Some(&file_env),
            Config {
                enable_whois: true, // irrelevant: overwrite("enable_whois") is false here
                ..Default::default()
            },
            Some(&["no_whois"]),
        );
        assert!(
            !merged.enable_whois,
            "--no-whois must force enable_whois=false even though the TOML file says true"
        );
    }

    /// Without `--no-whois`, file/env `enable_whois=true` must still apply normally.
    #[test]
    fn test_enable_whois_true_from_file_applies_without_no_whois_flag() {
        let file_env = FileConfig {
            enable_whois: Some(true),
            ..Default::default()
        };

        let merged = merge_file_env_and_cli(Some(&file_env), Config::default(), Some(&[]));
        assert!(
            merged.enable_whois,
            "file enable_whois=true must apply when --no-whois was not set"
        );
    }

    /// Adversarial: `scan_external_scripts` must parse permissive truthy string forms
    /// ("yes", "true", "1") from the config file / env map, not just canonical "true".
    #[test]
    fn test_scan_external_scripts_parses_permissive_truthy_strings() {
        for truthy in ["yes", "true", "1", "on", "YES", "True"] {
            let file_env = file_config_from_json(json!({"scan_external_scripts": truthy})).unwrap();

            let merged = merge_file_env_and_cli(Some(&file_env), Config::default(), Some(&[]));
            assert!(
                merged.scan_external_scripts,
                "scan_external_scripts={truthy:?} must parse to true"
            );
        }

        for falsy in ["no", "false", "0", "off"] {
            let file_env = file_config_from_json(json!({"scan_external_scripts": falsy})).unwrap();

            let merged = merge_file_env_and_cli(Some(&file_env), Config::default(), Some(&[]));
            assert!(
                !merged.scan_external_scripts,
                "scan_external_scripts={falsy:?} must parse to false"
            );
        }
    }

    #[test]
    fn test_fail_on_aliases_deserialize() {
        for alias in ["any-failure", "any_failure", "anyfailure", "ANY-FAILURE"] {
            let fc = file_config_from_json(json!({"fail_on": alias})).unwrap();
            assert_eq!(fc.fail_on, Some(FailOn::AnyFailure), "alias={alias}");
        }
        let pct = file_config_from_json(json!({"fail_on": "pct>"})).unwrap();
        assert_eq!(pct.fail_on, Some(FailOn::PctGreaterThan));
    }

    #[test]
    fn test_file_config_deserializes_via_config_crate_toml() {
        let settings = config::Config::builder()
            .add_source(config::File::from_str(
                r#"
                max_concurrency = 42
                enable_whois = true
                fail_on = "any-failure"
                scan_external_scripts = "yes"
                log_level = "debug"
                "#,
                config::FileFormat::Toml,
            ))
            .build()
            .expect("build");
        let fc: FileConfig = settings.try_deserialize().expect("deserialize FileConfig");
        assert_eq!(fc.max_concurrency, Some(42));
        assert_eq!(fc.enable_whois, Some(true));
        assert_eq!(fc.fail_on, Some(FailOn::AnyFailure));
        assert_eq!(fc.scan_external_scripts, Some(true));
        assert_eq!(fc.log_level, Some(LogLevel::Debug));
    }
}
