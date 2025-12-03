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
                    if let Ok((reader, metadata)) =
                        load_from_file(cache_file.to_str().unwrap()).await
                    {
                        let reader_arc = Arc::new(reader);
                        *GEOIP_ASN_READER.write().map_err(|e| {
                            anyhow::anyhow!("GeoIP ASN writer lock poisoned: {}", e)
                        })? = Some((reader_arc, metadata));
                        log::info!("GeoIP ASN database loaded from cache");
                    }
                }
            }
        }
    }

    Ok(())
}
