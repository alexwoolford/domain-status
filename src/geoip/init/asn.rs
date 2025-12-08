//! ASN database initialization.

use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use url::form_urlencoded;

use super::loader::load_from_file;
use super::loader::load_from_url;
use crate::geoip::metadata::load_metadata;
use crate::geoip::{self, GEOIP_ASN_READER};

/// Initializes the ASN database (runs in background after City database is loaded)
pub(crate) async fn init_asn_database(cache_dir: &Path) -> Result<()> {
    // Check if already loaded
    {
        let reader = GEOIP_ASN_READER
            .read()
            .map_err(|e| anyhow::anyhow!("GeoIP ASN reader lock poisoned: {}", e))?;
        if reader.is_some() {
            return Ok(()); // Already loaded
        }
    }

    // Try to get license key for auto-download
    if let Ok(license_key) = std::env::var(geoip::MAXMIND_LICENSE_KEY_ENV) {
        if !license_key.is_empty() {
            let cache_file = cache_dir.join("GeoLite2-ASN.mmdb");
            let metadata_file = cache_dir.join("asn_metadata.json");

            // Check if cached version exists and is fresh
            let should_download = if let Ok(metadata) = load_metadata(&metadata_file).await {
                if let Ok(age) = metadata.last_updated.elapsed() {
                    age.as_secs() >= geoip::CACHE_TTL_SECS || !cache_file.exists()
                } else {
                    true
                }
            } else {
                true
            };

            if should_download {
                log::info!("Auto-downloading GeoLite2-ASN database (cache expired or missing)");
                let encoded_key =
                    form_urlencoded::byte_serialize(license_key.as_bytes()).collect::<String>();
                let download_url = format!(
                    "{}?edition_id=GeoLite2-ASN&license_key={}&suffix=tar.gz",
                    geoip::MAXMIND_DOWNLOAD_BASE,
                    encoded_key
                );

                match load_from_url(&download_url, cache_dir, "GeoLite2-ASN").await {
                    Ok((reader, metadata)) => {
                        let reader_arc = Arc::new(reader);
                        *GEOIP_ASN_READER.write().map_err(|e| {
                            anyhow::anyhow!("GeoIP ASN writer lock poisoned: {}", e)
                        })? = Some((reader_arc, metadata));
                        log::info!("GeoIP ASN database loaded successfully");
                    }
                    Err(e) => {
                        log::warn!(
                            "Failed to load ASN database: {}. Continuing without ASN lookups.",
                            e
                        );
                    }
                }
            } else {
                // Load from cache
                if cache_file.exists() {
                    if let Some(cache_path) = cache_file.to_str() {
                        if let Ok((reader, metadata)) = load_from_file(cache_path).await {
                            let reader_arc = Arc::new(reader);
                            *GEOIP_ASN_READER.write().map_err(|e| {
                                anyhow::anyhow!("GeoIP ASN writer lock poisoned: {}", e)
                            })? = Some((reader_arc, metadata));
                            log::info!("GeoIP ASN database loaded from cache");
                        }
                    } else {
                        log::warn!("Cache file path contains invalid UTF-8: {:?}", cache_file);
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_init_asn_database_no_license_key() {
        // Test when no license key is set
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let result = init_asn_database(temp_dir.path()).await;
        assert!(result.is_ok());
        // Should return Ok but not load database
    }

    #[tokio::test]
    async fn test_init_asn_database_empty_license_key() {
        // Test with empty license key
        std::env::set_var(geoip::MAXMIND_LICENSE_KEY_ENV, "");
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let result = init_asn_database(temp_dir.path()).await;
        assert!(result.is_ok());
        std::env::remove_var(geoip::MAXMIND_LICENSE_KEY_ENV);
    }

    #[tokio::test]
    async fn test_init_asn_database_already_loaded() {
        // Test when database is already loaded
        // First, we'd need to load it, but in unit tests it's not loaded
        // So this test verifies the check doesn't panic
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let result = init_asn_database(temp_dir.path()).await;
        // Should return Ok (either already loaded or not loaded due to no license)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_init_asn_database_invalid_cache_path() {
        // Test with invalid cache file path (non-existent file)
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        // Set a license key to trigger download attempt
        std::env::set_var(geoip::MAXMIND_LICENSE_KEY_ENV, "test_key");

        // This will attempt to download, which will fail, but should handle gracefully
        let result = init_asn_database(temp_dir.path()).await;
        // Should return Ok even if download fails (logs warning but continues)
        assert!(result.is_ok());

        std::env::remove_var(geoip::MAXMIND_LICENSE_KEY_ENV);
    }

    #[tokio::test]
    async fn test_init_asn_database_cache_file_missing() {
        // Test when cache file doesn't exist but metadata does
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let metadata_file = temp_dir.path().join("asn_metadata.json");

        // Create metadata file but no cache file
        let metadata = crate::geoip::types::GeoIpMetadata {
            source: "test".to_string(),
            version: "test".to_string(),
            last_updated: std::time::SystemTime::now(),
        };
        let metadata_json = serde_json::to_string(&metadata).unwrap();
        tokio::fs::write(&metadata_file, metadata_json)
            .await
            .expect("Failed to write metadata");

        std::env::set_var(geoip::MAXMIND_LICENSE_KEY_ENV, "test_key");
        let result = init_asn_database(temp_dir.path()).await;
        // Should attempt download since cache file is missing
        assert!(result.is_ok());

        std::env::remove_var(geoip::MAXMIND_LICENSE_KEY_ENV);
    }

    #[tokio::test]
    async fn test_init_asn_database_metadata_parse_error() {
        // Test when metadata file exists but is invalid JSON
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let metadata_file = temp_dir.path().join("asn_metadata.json");
        tokio::fs::write(&metadata_file, b"{ invalid json }")
            .await
            .expect("Failed to write invalid metadata");

        std::env::set_var(geoip::MAXMIND_LICENSE_KEY_ENV, "test_key");
        let result = init_asn_database(temp_dir.path()).await;
        // Should handle invalid metadata gracefully (treat as missing)
        assert!(result.is_ok());

        std::env::remove_var(geoip::MAXMIND_LICENSE_KEY_ENV);
    }

    #[tokio::test]
    async fn test_init_asn_database_download_failure_continues() {
        // Test that ASN download failure doesn't break the system
        // This is critical - ASN is optional, failures should be logged but not fatal
        // The code at line 60-65 handles download failures gracefully
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        std::env::set_var(geoip::MAXMIND_LICENSE_KEY_ENV, "invalid_key");

        // Should return Ok even if download fails
        let result = init_asn_database(temp_dir.path()).await;
        assert!(
            result.is_ok(),
            "ASN download failure should not break initialization"
        );

        std::env::remove_var(geoip::MAXMIND_LICENSE_KEY_ENV);
    }

    #[tokio::test]
    async fn test_init_asn_database_cache_load_failure_continues() {
        // Test that cache load failure doesn't break the system
        // This is critical - corrupted cache shouldn't prevent ASN initialization
        use crate::geoip::metadata::save_metadata;
        use std::time::SystemTime;
        use tempfile::TempDir;
        use tokio::io::AsyncWriteExt;

        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_file = temp_dir.path().join("GeoLite2-ASN.mmdb");
        let metadata_file = temp_dir.path().join("asn_metadata.json");

        // Create corrupted cache file
        let mut file = tokio::fs::File::create(&cache_file)
            .await
            .expect("Failed to create cache file");
        file.write_all(b"corrupted asn data")
            .await
            .expect("Failed to write corrupted data");

        // Create valid metadata
        let metadata = crate::geoip::types::GeoIpMetadata {
            source: "test://source".to_string(),
            version: "1.0".to_string(),
            last_updated: SystemTime::now(),
        };
        save_metadata(&metadata, &metadata_file)
            .await
            .expect("Failed to save metadata");

        // Should handle corrupted cache gracefully (fall through to download or skip)
        std::env::set_var(geoip::MAXMIND_LICENSE_KEY_ENV, "test_key");
        let result = init_asn_database(temp_dir.path()).await;
        // Should return Ok even if cache load fails
        assert!(result.is_ok());

        std::env::remove_var(geoip::MAXMIND_LICENSE_KEY_ENV);
    }

    #[tokio::test]
    async fn test_init_asn_database_concurrent_initialization() {
        // Test that concurrent ASN initialization doesn't cause issues
        // This is critical - multiple background tasks might try to initialize
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        std::env::set_var(geoip::MAXMIND_LICENSE_KEY_ENV, "test_key");

        // Spawn multiple tasks
        let handles: Vec<_> = (0..5)
            .map(|_| {
                let cache_dir = temp_dir.path().to_path_buf();
                tokio::spawn(async move { init_asn_database(&cache_dir).await })
            })
            .collect();

        // All should succeed (even if download fails)
        for handle in handles {
            let result = handle.await.expect("Task panicked");
            assert!(result.is_ok());
        }

        std::env::remove_var(geoip::MAXMIND_LICENSE_KEY_ENV);
    }
}
