//! GeoIP database loading from files and URLs.

use anyhow::{Context, Result};
use maxminddb::Reader;
use std::path::Path;
use std::time::Duration;

use crate::geoip::extract::extract_mmdb_from_tar_gz;
use crate::geoip::metadata::{extract_metadata, load_metadata, save_metadata};
use crate::geoip::types::GeoIpMetadata;
use crate::geoip::{self};

/// Loads GeoIP database from a local file path
pub(crate) async fn load_from_file(path: &str) -> Result<(Reader<Vec<u8>>, GeoIpMetadata)> {
    log::info!("Loading GeoIP database from: {}", path);

    let db_bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("Failed to read GeoIP database from {}", path))?;

    // Create reader from owned bytes
    let reader = Reader::from_source(db_bytes.clone())
        .with_context(|| format!("Failed to parse GeoIP database from {}", path))?;

    // Extract metadata from database
    let metadata = extract_metadata(&reader, path)?;

    // Create reader with owned data
    let reader_owned = Reader::from_source(db_bytes)
        .with_context(|| format!("Failed to create owned reader from {}", path))?;

    Ok((reader_owned, metadata))
}

/// Downloads GeoIP database from URL and caches it locally.
///
/// Handles both direct .mmdb file downloads and tar.gz archives (MaxMind format).
///
/// # Arguments
///
/// * `url` - Download URL
/// * `cache_dir` - Cache directory
/// * `db_name` - Database name for cache file (e.g., "GeoLite2-City" or "GeoLite2-ASN")
pub(crate) async fn load_from_url(
    url: &str,
    cache_dir: &Path,
    db_name: &str,
) -> Result<(Reader<Vec<u8>>, GeoIpMetadata)> {
    // Create cache directory if it doesn't exist
    tokio::fs::create_dir_all(cache_dir)
        .await
        .with_context(|| format!("Failed to create cache directory: {:?}", cache_dir))?;

    let cache_file = cache_dir.join(format!("{}.mmdb", db_name));
    let metadata_file = cache_dir.join(format!("{}_metadata.json", db_name.to_lowercase()));

    // Check if cached version exists and is fresh
    if let Ok(metadata) = load_metadata(&metadata_file).await {
        if let Ok(age) = metadata.last_updated.elapsed() {
            if age.as_secs() < geoip::CACHE_TTL_SECS {
                // Cache is fresh, try to load
                if cache_file.exists() {
                    if let Ok((reader, _)) = load_from_file(cache_file.to_str().unwrap()).await {
                        log::info!("Loaded GeoIP database from cache: {:?}", cache_file);
                        return Ok((reader, metadata));
                    }
                }
            }
        }
    }

    // Download database
    log::info!("Downloading GeoIP database from: {}", url);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300)) // 5 minutes for large file
        .build()?;

    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let error_body = response
            .text()
            .await
            .unwrap_or_else(|_| "No error details".to_string());
        log::error!("MaxMind API error response: {}", error_body);
        return Err(anyhow::anyhow!(
            "Failed to download GeoIP database: {} - {}",
            status,
            error_body
        ));
    }

    let downloaded_bytes = response.bytes().await?.to_vec();

    // Extract .mmdb file from tar.gz if needed, or use directly if it's already .mmdb
    let db_bytes = if url.ends_with(".tar.gz") || url.contains("suffix=tar.gz") {
        extract_mmdb_from_tar_gz(&downloaded_bytes, db_name)?
    } else if url.ends_with(".mmdb") {
        // Direct .mmdb file download
        downloaded_bytes
    } else {
        // Try to detect format - if it looks like tar.gz, extract it
        if downloaded_bytes.len() > 2 && downloaded_bytes[0] == 0x1f && downloaded_bytes[1] == 0x8b
        {
            // Gzip magic number
            extract_mmdb_from_tar_gz(&downloaded_bytes, db_name)?
        } else {
            // Assume it's already a .mmdb file
            downloaded_bytes
        }
    };

    // Save to cache
    tokio::fs::write(&cache_file, &db_bytes)
        .await
        .with_context(|| format!("Failed to write cache file: {:?}", cache_file))?;

    // Parse database to extract metadata (temporary reader for metadata extraction)
    let reader_temp = Reader::from_source(db_bytes.as_slice())
        .with_context(|| "Failed to parse downloaded GeoIP database")?;

    let metadata = extract_metadata(&reader_temp, url)?;

    // Create reader with owned data
    let reader = Reader::from_source(db_bytes)
        .with_context(|| "Failed to create owned reader from downloaded database")?;

    // Save metadata
    save_metadata(&metadata, &metadata_file).await?;

    Ok((reader, metadata))
}
