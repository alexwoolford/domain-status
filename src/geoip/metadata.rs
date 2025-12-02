//! Metadata management for GeoIP databases.
//!
//! This module provides functions to extract, load, and save GeoIP database metadata.

use anyhow::Result;
use maxminddb::Reader;
use std::path::Path;
use std::time::SystemTime;

use super::types::GeoIpMetadata;

/// Extracts metadata from a GeoIP database
pub(crate) fn extract_metadata<T: AsRef<[u8]>>(
    reader: &Reader<T>,
    source: &str,
) -> Result<GeoIpMetadata> {
    // Try to get build epoch from database metadata
    // MaxMind databases have a build_epoch field in their metadata
    let version = format!("build_{}", reader.metadata.build_epoch);

    Ok(GeoIpMetadata {
        source: source.to_string(),
        version,
        last_updated: SystemTime::now(),
    })
}

/// Loads metadata from cache file
pub(crate) async fn load_metadata(metadata_file: &Path) -> Result<GeoIpMetadata> {
    let content = tokio::fs::read_to_string(metadata_file).await?;
    let metadata: GeoIpMetadata = serde_json::from_str(&content)?;
    Ok(metadata)
}

/// Saves metadata to cache file
pub(crate) async fn save_metadata(metadata: &GeoIpMetadata, metadata_file: &Path) -> Result<()> {
    let content = serde_json::to_string_pretty(metadata)?;
    tokio::fs::write(metadata_file, content).await?;
    Ok(())
}

