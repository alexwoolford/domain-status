//! ASN database initialization.

use anyhow::Result;
use std::path::Path;
use std::sync::Arc;

use super::loader::{geoip_cache_paths, load_from_file, load_from_url};
use super::maxmind_download_url;
use crate::geoip::metadata::load_metadata;
use crate::geoip::{self, GEOIP_ASN_READER};

fn asn_reader_loaded() -> Result<bool> {
    let reader = GEOIP_ASN_READER
        .read()
        .map_err(|e| anyhow::anyhow!("GeoIP ASN reader lock poisoned: {e}"))?;
    Ok(reader.is_some())
}

fn store_asn_reader(
    reader: maxminddb::Reader<Vec<u8>>,
    metadata: geoip::GeoIpMetadata,
) -> Result<()> {
    let reader_arc = Arc::new(reader);
    *GEOIP_ASN_READER
        .write()
        .map_err(|e| anyhow::anyhow!("GeoIP ASN writer lock poisoned: {e}"))? =
        Some((reader_arc, metadata));
    Ok(())
}

async fn try_load_asn_from_cache(cache_file: &Path) -> Result<bool> {
    let Some(path) = cache_file.to_str() else {
        log::warn!(
            "Cache file path contains invalid UTF-8: {}",
            cache_file.display()
        );
        return Ok(false);
    };
    match load_from_file(path).await {
        Ok((reader, metadata)) => {
            store_asn_reader(reader, metadata)?;
            log::info!("GeoIP ASN database loaded from cache");
            Ok(true)
        }
        Err(e) => {
            log::warn!("Failed to load cached ASN database: {e}");
            Ok(false)
        }
    }
}

async fn try_download_asn(license_key: &str, cache_dir: &Path) -> Result<bool> {
    log::info!("Auto-downloading GeoLite2-ASN database (cache expired or missing)");
    let download_url = maxmind_download_url("GeoLite2-ASN", license_key);
    match load_from_url(&download_url, cache_dir, "GeoLite2-ASN").await {
        Ok((reader, metadata)) => {
            store_asn_reader(reader, metadata)?;
            log::info!("GeoIP ASN database loaded successfully");
            Ok(true)
        }
        Err(e) => {
            log::warn!("Failed to load ASN database: {e}. Continuing without ASN lookups.");
            Ok(false)
        }
    }
}

/// Initializes the ASN database after the City database is loaded.
///
/// Uses a cached `GeoLite2-ASN.mmdb` even when `MAXMIND_LICENSE_KEY` is unset.
/// Auto-download still requires the license key.
pub(crate) async fn init_asn_database(cache_dir: &Path) -> Result<()> {
    if asn_reader_loaded()? {
        return Ok(());
    }

    let (cache_file, metadata_file) = geoip_cache_paths(cache_dir, "GeoLite2-ASN");
    let license_key = std::env::var(geoip::MAXMIND_LICENSE_KEY_ENV)
        .ok()
        .filter(|key| !key.is_empty());

    let should_download = license_key.is_some()
        && match load_metadata(&metadata_file).await {
            Ok(metadata) => {
                crate::utils::cache::cache_ttl_exceeded(
                    metadata.last_updated,
                    geoip::CACHE_TTL_SECS,
                    true,
                ) || !cache_file.exists()
            }
            Err(_) => true,
        };

    if should_download {
        if let Some(key) = license_key.as_deref() {
            if try_download_asn(key, cache_dir).await? {
                return Ok(());
            }
        }
    }

    log::debug!(
        "ASN MMDB candidate {} (exists={})",
        cache_file.display(),
        cache_file.exists()
    );

    if cache_file.exists() {
        try_load_asn_from_cache(&cache_file).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geoip::metadata::save_metadata;
    use crate::geoip::test_support::LicenseKeyEnvGuard;
    use crate::geoip::types::GeoIpMetadata;
    use std::time::{Duration, SystemTime};
    use tempfile::TempDir;

    fn cache_paths(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
        super::super::loader::geoip_cache_paths(dir, "GeoLite2-ASN")
    }

    fn assert_asn_degrades_unloaded(result: Result<()>) {
        result.expect("ASN init must degrade, not abort");
        assert!(
            crate::geoip::GEOIP_ASN_READER
                .read()
                .expect("ASN reader lock")
                .is_none(),
            "ASN reader must stay unloaded"
        );
    }

    #[tokio::test]
    async fn test_init_asn_database_no_or_empty_license_degrades() {
        let temp_dir = TempDir::new().expect("temp dir");
        {
            let _license_env = LicenseKeyEnvGuard::apply(None);
            assert_asn_degrades_unloaded(init_asn_database(temp_dir.path()).await);
        }
        {
            let _license_env = LicenseKeyEnvGuard::apply(Some(""));
            assert_asn_degrades_unloaded(init_asn_database(temp_dir.path()).await);
        }
    }

    #[tokio::test]
    async fn test_init_asn_database_no_license_still_tries_existing_cache() {
        let _license_env = LicenseKeyEnvGuard::apply(None);
        let temp_dir = TempDir::new().expect("temp dir");
        let (cache_file, _) = cache_paths(temp_dir.path());
        tokio::fs::write(&cache_file, b"not a real mmdb")
            .await
            .expect("write");
        assert_asn_degrades_unloaded(init_asn_database(temp_dir.path()).await);
    }

    #[tokio::test]
    async fn test_init_asn_database_download_failure_continues() {
        let temp_dir = TempDir::new().expect("temp dir");
        let blocker = temp_dir.path().join("not-a-directory");
        tokio::fs::write(&blocker, b"occupied")
            .await
            .expect("write");
        let _license_env = LicenseKeyEnvGuard::apply(Some("test_key"));
        assert_asn_degrades_unloaded(init_asn_database(&blocker).await);
    }

    #[tokio::test]
    async fn test_init_asn_database_corrupt_cache_with_real_metadata_name() {
        let temp_dir = TempDir::new().expect("temp dir");
        let (cache_file, metadata_file) = cache_paths(temp_dir.path());
        tokio::fs::write(&cache_file, b"corrupted asn data")
            .await
            .expect("write");
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
        let _license_env = LicenseKeyEnvGuard::apply(None);
        assert_asn_degrades_unloaded(init_asn_database(temp_dir.path()).await);
    }

    #[tokio::test]
    async fn test_init_asn_database_expired_or_missing_cache_uses_metadata_path() {
        let temp_dir = TempDir::new().expect("temp dir");
        let (cache_file, metadata_file) = cache_paths(temp_dir.path());
        save_metadata(
            &GeoIpMetadata {
                source: "test://source".to_string(),
                version: "1.0".to_string(),
                last_updated: SystemTime::now() - Duration::from_secs(geoip::CACHE_TTL_SECS),
            },
            &metadata_file,
        )
        .await
        .expect("save");
        tokio::fs::write(&cache_file, b"stale")
            .await
            .expect("write");
        let _license_env = LicenseKeyEnvGuard::apply(None);
        assert_asn_degrades_unloaded(init_asn_database(temp_dir.path()).await);

        tokio::fs::remove_file(&cache_file).await.ok();
        assert_asn_degrades_unloaded(init_asn_database(temp_dir.path()).await);
    }

    #[tokio::test]
    async fn test_init_asn_database_invalid_metadata_json() {
        let temp_dir = TempDir::new().expect("temp dir");
        let (_, metadata_file) = cache_paths(temp_dir.path());
        tokio::fs::write(&metadata_file, b"{ invalid json }")
            .await
            .expect("write");
        let _license_env = LicenseKeyEnvGuard::apply(None);
        assert_asn_degrades_unloaded(init_asn_database(temp_dir.path()).await);
    }

    #[tokio::test]
    async fn test_init_asn_database_future_timestamp_fail_closed() {
        let temp_dir = TempDir::new().expect("temp dir");
        let (_, metadata_file) = cache_paths(temp_dir.path());
        save_metadata(
            &GeoIpMetadata {
                source: "test://source".to_string(),
                version: "1.0".to_string(),
                last_updated: SystemTime::now() + Duration::from_secs(86400 * 365),
            },
            &metadata_file,
        )
        .await
        .expect("save");
        let _license_env = LicenseKeyEnvGuard::apply(None);
        assert_asn_degrades_unloaded(init_asn_database(temp_dir.path()).await);
    }
}
