//! `GeoIP` database initialization and loading.
//!
//! This module provides functions to initialize and load `GeoIP` databases from
//! local files or automatic downloads from `MaxMind`.

mod asn;
mod loader;

use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use url::form_urlencoded;

use crate::geoip::metadata::{cleanup_geoip_tmp_orphans, load_metadata};
use crate::geoip::types::GeoIpMetadata;
use crate::geoip::{self, GEOIP_CITY_READER};

use loader::{geoip_cache_paths, load_from_file, load_from_url};

/// Strip query string so `MaxMind` `license_key=` is not written to scan logs.
#[must_use]
pub(super) fn source_for_log(path: &str) -> &str {
    path.split_once('?').map_or(path, |(base, _)| base)
}

/// `MaxMind` permalink for a `GeoLite2` edition (`GeoLite2-City` or `GeoLite2-ASN`).
#[must_use]
pub(super) fn maxmind_download_url(edition_id: &str, license_key: &str) -> String {
    let encoded_key = form_urlencoded::byte_serialize(license_key.as_bytes()).collect::<String>();
    format!(
        "{}?edition_id={edition_id}&license_key={encoded_key}&suffix=tar.gz",
        geoip::MAXMIND_DOWNLOAD_BASE
    )
}

/// Resolves a `MaxMind` download URL or cached `.mmdb` path when `MAXMIND_LICENSE_KEY` is set.
///
/// Returns `None` when the license key is unset or empty (caller decides how to disable).
async fn resolve_from_license_key(cache_path: &Path) -> Option<String> {
    let license_key = std::env::var(geoip::MAXMIND_LICENSE_KEY_ENV).ok()?;
    if license_key.is_empty() {
        return None;
    }

    let (cache_file, metadata_file) = geoip_cache_paths(cache_path, "GeoLite2-City");

    let should_download = if let Ok(metadata) = load_metadata(&metadata_file).await {
        crate::utils::cache::cache_ttl_exceeded(metadata.last_updated, geoip::CACHE_TTL_SECS, true)
            || !cache_file.exists()
    } else {
        true
    };

    if should_download {
        log::info!("Auto-downloading GeoLite2-City database (cache expired or missing)");
        Some(maxmind_download_url("GeoLite2-City", &license_key))
    } else {
        log::info!("Using cached GeoIP database");
        Some(cache_file.to_string_lossy().to_string())
    }
}

/// Chooses the `GeoIP` source: explicit path/URL, license-key auto-download, or disabled.
///
/// When `--geoip` is a local path that does not exist and a license key is available,
/// falls back to the same auto-download/cache path used when `--geoip` is omitted.
async fn resolve_geoip_source(
    geoip_path: Option<&str>,
    cache_path: &Path,
) -> Result<Option<String>> {
    match geoip_path {
        Some(p) if p.starts_with("http://") || p.starts_with("https://") => Ok(Some(p.to_string())),
        Some(p) if Path::new(p).exists() => Ok(Some(p.to_string())),
        Some(p) => {
            // Missing local path: fall back to license-key download when possible.
            if let Some(auto) = resolve_from_license_key(cache_path).await {
                log::warn!(
                    "GeoIP path '{p}' not found; falling back to MaxMind auto-download/cache \
                     (MAXMIND_LICENSE_KEY is set)"
                );
                Ok(Some(auto))
            } else {
                // Keep the path so load_from_file returns a clear not-found error.
                Ok(Some(p.to_string()))
            }
        }
        None => {
            if let Some(auto) = resolve_from_license_key(cache_path).await {
                Ok(Some(auto))
            } else if std::env::var(geoip::MAXMIND_LICENSE_KEY_ENV)
                .map(|k| k.is_empty())
                .unwrap_or(false)
            {
                log::info!(
                    "GeoIP lookup disabled (no database path provided and MAXMIND_LICENSE_KEY is empty)"
                );
                Ok(None)
            } else {
                log::info!(
                    "GeoIP lookup disabled (no database path provided and MAXMIND_LICENSE_KEY not set)"
                );
                Ok(None)
            }
        }
    }
}

/// Initializes the `GeoIP` database from a local file path or automatic download.
///
/// The database is cached in memory and can be refreshed by calling this function
/// again with a different path or after the cache expires.
///
/// # Arguments
///
/// * `geoip_path` - Optional path to the `MaxMind` `GeoLite2` database file (.mmdb) or download URL.
///   If None, will attempt automatic download using `MAXMIND_LICENSE_KEY` env var.
///   If a local path is missing and `MAXMIND_LICENSE_KEY` is set, falls back to auto-download.
/// * `cache_dir` - Optional cache directory for downloaded databases
///
/// # Returns
///
/// Returns the metadata about the loaded database, including version information.
///
/// # Automatic Download
///
/// If `geoip_path` is None but `MAXMIND_LICENSE_KEY` environment variable is set,
/// the function will automatically download the latest GeoLite2-City database.
pub async fn init_geoip(
    geoip_path: Option<&str>,
    cache_dir: Option<&Path>,
) -> Result<Option<GeoIpMetadata>> {
    let cache_path = cache_dir.map_or_else(
        || crate::cache_paths::geoip_dir(&crate::cache_paths::resolve_cache_root(None)),
        std::path::Path::to_path_buf,
    );

    cleanup_geoip_tmp_orphans(&cache_path).await;

    let Some(path) = resolve_geoip_source(geoip_path, &cache_path).await? else {
        return Ok(None);
    };

    // Check if City database already loaded
    let should_load = {
        let reader = GEOIP_CITY_READER
            .read()
            .map_err(|e| anyhow::anyhow!("GeoIP City reader lock poisoned: {e}"))?;
        if let Some((_, ref metadata)) = *reader {
            // Check if source matches
            if metadata.source == path {
                log::info!(
                    "GeoIP City database already loaded: {}",
                    source_for_log(&path)
                );
                false // Don't reload, but still try ASN
            } else {
                true // Different source, reload
            }
        } else {
            true // Not loaded yet
        }
    };

    let metadata = if should_load {
        let (reader, metadata) = if path.starts_with("http://") || path.starts_with("https://") {
            load_from_url(&path, &cache_path, "GeoLite2-City").await?
        } else {
            load_from_file(&path).await?
        };

        let reader_arc = Arc::new(reader);
        *GEOIP_CITY_READER
            .write()
            .map_err(|e| anyhow::anyhow!("GeoIP City writer lock poisoned: {e}"))? =
            Some((reader_arc, metadata.clone()));
        log::info!("GeoIP City database loaded successfully");
        metadata
    } else {
        let reader = GEOIP_CITY_READER
            .read()
            .map_err(|e| anyhow::anyhow!("GeoIP City reader lock poisoned: {e}"))?;
        reader
            .as_ref()
            .map(|(_, metadata)| metadata.clone())
            .ok_or_else(|| {
                anyhow::anyhow!("GeoIP City reader vanished after already-loaded check")
            })?
    };

    log::info!(
        "Initializing GeoIP ASN from {} (city source {})",
        cache_path.display(),
        source_for_log(&path)
    );
    if let Err(e) = asn::init_asn_database(&cache_path).await {
        log::warn!("Failed to initialize ASN database: {e}");
    }

    Ok(Some(metadata))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geoip::metadata::save_metadata;
    use crate::geoip::types::GeoIpMetadata;
    use std::time::SystemTime;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_init_geoip_no_path_no_license() {
        let _license_env = geoip::test_support::LicenseKeyEnvGuard::apply(None);
        let metadata = init_geoip(None, None)
            .await
            .expect("disabled GeoIP must not abort init");
        if crate::geoip::GEOIP_CITY_READER
            .read()
            .expect("city reader lock")
            .is_none()
        {
            assert!(
                metadata.is_none(),
                "no path and no license must leave GeoIP unloaded"
            );
        }
    }

    #[tokio::test]
    async fn test_init_geoip_empty_license_key() {
        let _license_env = geoip::test_support::LicenseKeyEnvGuard::apply(Some(""));
        let metadata = init_geoip(None, None)
            .await
            .expect("empty license key must not abort init");
        assert!(
            metadata.is_none(),
            "empty MAXMIND_LICENSE_KEY must leave GeoIP disabled"
        );
    }

    #[tokio::test]
    async fn test_init_geoip_invalid_path() {
        let _license_env = geoip::test_support::LicenseKeyEnvGuard::apply(None);
        let result = init_geoip(Some("nonexistent/path/to/database.mmdb"), None).await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Failed to read")
                || error_msg.contains("No such file")
                || error_msg.contains("not found"),
            "Expected file not found error, got: {error_msg}"
        );
    }

    #[tokio::test]
    async fn test_missing_local_geoip_falls_back_to_license_key() {
        let temp_dir = TempDir::new().expect("temp dir");
        let _license_env = geoip::test_support::LicenseKeyEnvGuard::apply(Some("test-license-key"));
        let resolved =
            resolve_geoip_source(Some("nonexistent/GeoLite2-City.mmdb"), temp_dir.path())
                .await
                .expect("resolve should succeed");
        let path = resolved.expect("should fall back to license-key source");
        assert!(
            path.starts_with("https://"),
            "expected MaxMind download URL, got: {path}"
        );
        assert!(
            path.contains("edition_id=GeoLite2-City"),
            "expected City edition in URL: {path}"
        );
        assert!(
            !path.contains("nonexistent"),
            "should not keep the missing local path when license key is set: {path}"
        );
    }

    #[tokio::test]
    async fn test_missing_local_geoip_without_license_keeps_path() {
        let _license_env = geoip::test_support::LicenseKeyEnvGuard::apply(None);
        let temp_dir = TempDir::new().expect("temp dir");
        let missing = "nonexistent/GeoLite2-City.mmdb";
        let resolved = resolve_geoip_source(Some(missing), temp_dir.path())
            .await
            .expect("resolve should succeed");
        assert_eq!(
            resolved.as_deref(),
            Some(missing),
            "without a license key, keep the path so load fails clearly"
        );
    }

    #[tokio::test]
    async fn test_init_geoip_http_url_is_download_not_file() {
        let temp_dir = TempDir::new().expect("temp dir");
        // Loopback is SSRF-rejected in validate_url_safe — proves URL vs file routing
        // without a live download (the download client has a 300s timeout).
        let result = init_geoip(Some("http://127.0.0.1/db.mmdb"), Some(temp_dir.path())).await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Unsafe"),
            "HTTP GeoIP source must fail as a download, not a missing file: {error_msg}"
        );
        assert!(
            !error_msg.contains("No such file"),
            "HTTP GeoIP source must not take the local-file path: {error_msg}"
        );
    }

    #[tokio::test]
    async fn test_init_geoip_invalid_city_file_fails_before_asn_download() {
        let temp_dir = TempDir::new().expect("temp dir");
        let _license_env = geoip::test_support::LicenseKeyEnvGuard::apply(None);
        let bad_db = temp_dir.path().join("not-a-database.mmdb");
        std::fs::write(&bad_db, b"not-a-valid-mmdb").expect("write invalid fixture");
        let bad_db_path = bad_db.to_str().expect("UTF-8");
        let start = std::time::Instant::now();
        let result = init_geoip(Some(bad_db_path), Some(temp_dir.path())).await;
        let elapsed = start.elapsed();
        assert!(result.is_err());
        assert!(
            elapsed.as_secs() < 1,
            "invalid City MMDB must fail locally before any ASN download"
        );
    }

    #[test]
    fn test_asn_init_uses_geoip_cache_dir_not_city_url_parent() {
        let cache = Path::new("/var/cache/domain_status/geoip");
        let city_url =
            "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&suffix=tar.gz";
        let url_parent = Path::new(city_url).parent();
        assert_ne!(
            url_parent.map(Path::as_os_str),
            Some(cache.as_os_str()),
            "parent(City download URL) must not be treated as the GeoIP cache dir"
        );
        assert_eq!(
            source_for_log(
                "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=secret&suffix=tar.gz"
            ),
            "https://download.maxmind.com/app/geoip_download",
            "MaxMind license query string must not appear in GeoIP logs"
        );
        assert_eq!(
            source_for_log("/var/cache/domain_status/geoip/GeoLite2-City.mmdb"),
            "/var/cache/domain_status/geoip/GeoLite2-City.mmdb"
        );
        let url = maxmind_download_url("GeoLite2-City", "secret");
        assert!(url.contains("edition_id=GeoLite2-City"));
        assert_eq!(
            source_for_log(&url),
            "https://download.maxmind.com/app/geoip_download"
        );
    }

    #[tokio::test]
    async fn test_init_geoip_cache_path_default_vs_provided() {
        let _license_env = geoip::test_support::LicenseKeyEnvGuard::apply(None);
        let result1 = init_geoip(None, None).await;
        assert!(result1.is_ok());
        let temp_dir = TempDir::new().expect("temp dir");
        let result2 = init_geoip(None, Some(temp_dir.path())).await;
        assert!(result2.is_ok());
        let default_path =
            crate::cache_paths::geoip_dir(&crate::cache_paths::resolve_cache_root(None));
        assert!(
            default_path.ends_with("geoip") || default_path.to_string_lossy().contains("geoip"),
            "default geoip cache should be under shared root: {}",
            default_path.display()
        );
    }

    #[tokio::test]
    async fn test_init_geoip_automatic_download_with_fresh_cache() {
        let temp_dir = TempDir::new().expect("temp dir");
        let (cache_file, metadata_file) = geoip_cache_paths(temp_dir.path(), "GeoLite2-City");
        save_metadata(
            &GeoIpMetadata {
                source: "test://source".to_string(),
                version: "1.0".to_string(),
                last_updated: SystemTime::now(),
            },
            &metadata_file,
        )
        .await
        .expect("save");
        tokio::fs::write(&cache_file, b"minimal cache")
            .await
            .expect("write");
        let _license_env = geoip::test_support::LicenseKeyEnvGuard::apply(Some("test_key"));
        let result = init_geoip(None, Some(temp_dir.path())).await;
        assert!(
            result.is_err(),
            "fresh City cache with a non-MMDB body must fail on parse, not download"
        );
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Invalid MaxMind")
                || error_msg.contains("MMDB")
                || error_msg.contains("parse")
                || error_msg.contains("Failed to"),
            "expected local cache parse failure, got: {error_msg}"
        );
        assert!(
            !error_msg.contains("download.maxmind.com"),
            "fresh cache must not fall through to MaxMind download: {error_msg}"
        );
    }

    #[tokio::test]
    async fn test_init_geoip_missing_file_fails_consistently() {
        let _license_env = geoip::test_support::LicenseKeyEnvGuard::apply(None);
        let temp_dir = TempDir::new().expect("temp dir");
        let result1 = init_geoip(Some("nonexistent.mmdb"), Some(temp_dir.path())).await;
        let result2 = init_geoip(Some("nonexistent.mmdb"), Some(temp_dir.path())).await;
        assert!(result1.is_err(), "missing MMDB must fail the first init");
        assert!(
            result2.is_err(),
            "missing MMDB must fail again (nothing was loaded to short-circuit)"
        );
    }
}
