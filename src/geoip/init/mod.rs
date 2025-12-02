//! GeoIP database initialization and loading.
//!
//! This module provides functions to initialize and load GeoIP databases from
//! local files or automatic downloads from MaxMind.

mod asn;
mod loader;

use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use url::form_urlencoded;

use crate::geoip::metadata::load_metadata;
use crate::geoip::types::GeoIpMetadata;
use crate::geoip::{self, GEOIP_CITY_READER};

use loader::{load_from_file, load_from_url};

/// Initializes the GeoIP database from a local file path or automatic download.
///
/// The database is cached in memory and can be refreshed by calling this function
/// again with a different path or after the cache expires.
///
/// # Arguments
///
/// * `geoip_path` - Optional path to the MaxMind GeoLite2 database file (.mmdb) or download URL.
///   If None, will attempt automatic download using MAXMIND_LICENSE_KEY env var.
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
    let cache_path = cache_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from(geoip::DEFAULT_CACHE_DIR));

    // Determine the source path
    let path = match geoip_path {
        Some(p) => p.to_string(),
        None => {
            // Try automatic download if license key is available
            if let Ok(license_key) = std::env::var(geoip::MAXMIND_LICENSE_KEY_ENV) {
                if !license_key.is_empty() {
                    // Check cache first
                    let cache_file = cache_path.join("GeoLite2-City.mmdb");
                    let metadata_file = cache_path.join("metadata.json");

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
                        log::info!(
                            "Auto-downloading GeoLite2-City database (cache expired or missing)"
                        );
                        // URL-encode the license key to handle special characters
                        let encoded_key = form_urlencoded::byte_serialize(license_key.as_bytes())
                            .collect::<String>();
                        let download_url = format!(
                            "{}?edition_id=GeoLite2-City&license_key={}&suffix=tar.gz",
                            geoip::MAXMIND_DOWNLOAD_BASE, encoded_key
                        );
                        download_url
                    } else {
                        // Use cached file
                        log::info!("Using cached GeoIP database");
                        cache_file.to_string_lossy().to_string()
                    }
                } else {
                    log::info!("GeoIP lookup disabled (no database path provided and MAXMIND_LICENSE_KEY is empty)");
                    return Ok(None);
                }
            } else {
                log::info!("GeoIP lookup disabled (no database path provided and MAXMIND_LICENSE_KEY not set)");
                return Ok(None);
            }
        }
    };

    // Check if City database already loaded
    let should_load = {
        let reader = GEOIP_CITY_READER
            .read()
            .map_err(|e| anyhow::anyhow!("GeoIP City reader lock poisoned: {}", e))?;
        if let Some((_, ref metadata)) = *reader {
            // Check if source matches
            if metadata.source == path {
                log::info!("GeoIP City database already loaded: {}", path);
                false // Don't reload, but still try ASN
            } else {
                true // Different source, reload
            }
        } else {
            true // Not loaded yet
        }
    };

    if should_load {
        // Load City database
        let (reader, metadata) = if path.starts_with("http://") || path.starts_with("https://") {
            load_from_url(&path, &cache_path, "GeoLite2-City").await?
        } else {
            load_from_file(&path).await?
        };

        let reader_arc = Arc::new(reader);
        *GEOIP_CITY_READER.write().map_err(|e| {
            anyhow::anyhow!("GeoIP City writer lock poisoned: {}", e)
        })? = Some((reader_arc, metadata.clone()));
        log::info!("GeoIP City database loaded successfully");

        // Try to initialize ASN database in background (non-blocking)
        let cache_path_clone = cache_path.clone();
        tokio::spawn(async move {
            if let Err(e) = asn::init_asn_database(&cache_path_clone).await {
                log::warn!("Failed to initialize ASN database: {}", e);
            }
        });

        Ok(Some(metadata))
    } else {
        // Already loaded, just return metadata
        let reader = GEOIP_CITY_READER
            .read()
            .map_err(|e| anyhow::anyhow!("GeoIP City reader lock poisoned: {}", e))?;
        Ok(reader.as_ref().map(|(_, metadata)| metadata.clone()))
    }
}

