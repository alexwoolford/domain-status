//! Shared cache root for fingerprints, `GeoIP`, WHOIS, and User-Agent data.
//!
//! Resolution order for the cache root:
//! 1. Explicit `--cache-dir` / [`Config::cache_dir`](crate::config::Config::cache_dir)
//! 2. `DOMAIN_STATUS_CACHE_DIR` environment variable
//! 3. XDG cache home: `~/.cache/domain_status` (macOS/Linux) or platform equivalent
//! 4. Fallback: `./domain_status` under the process cwd when no cache home exists
//!
//! The `SQLite` database and log file are **outputs**, not caches — they stay
//! under `--db-path` / `--log-file` (cwd by default).

use std::path::{Path, PathBuf};

/// Env var that overrides the default XDG cache root.
pub const CACHE_DIR_ENV: &str = "DOMAIN_STATUS_CACHE_DIR";

/// Resolve the shared cache root.
#[must_use]
pub fn resolve_cache_root(explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    if let Ok(path) = std::env::var(CACHE_DIR_ENV) {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("domain_status")
}

/// Fingerprint ruleset cache subdirectory.
#[must_use]
pub fn fingerprints_dir(root: &Path) -> PathBuf {
    root.join("fingerprints")
}

/// `GeoIP` MMDB cache subdirectory.
#[must_use]
pub fn geoip_dir(root: &Path) -> PathBuf {
    root.join("geoip")
}

/// WHOIS/RDAP JSON cache subdirectory.
#[must_use]
pub fn whois_dir(root: &Path) -> PathBuf {
    root.join("whois")
}

/// Chrome User-Agent version cache subdirectory.
#[must_use]
pub fn user_agent_dir(root: &Path) -> PathBuf {
    root.join("user_agent")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_path_wins() {
        let explicit = PathBuf::from("/tmp/ds-explicit-cache");
        let resolved = resolve_cache_root(Some(&explicit));
        assert_eq!(resolved, explicit);
    }

    #[test]
    fn default_root_ends_with_domain_status() {
        let resolved = resolve_cache_root(None);
        assert_eq!(
            resolved.file_name().and_then(|s| s.to_str()),
            Some("domain_status")
        );
    }

    #[test]
    fn subdirs_are_under_root() {
        let root = PathBuf::from("/cache/root");
        assert_eq!(fingerprints_dir(&root), root.join("fingerprints"));
        assert_eq!(geoip_dir(&root), root.join("geoip"));
        assert_eq!(whois_dir(&root), root.join("whois"));
        assert_eq!(user_agent_dir(&root), root.join("user_agent"));
    }
}
