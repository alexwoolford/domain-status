//! Metadata management for `GeoIP` databases.
//!
//! This module provides functions to extract, load, and save `GeoIP` database metadata.

use anyhow::Result;
use maxminddb::Reader;
use std::path::Path;
use std::time::SystemTime;

use super::types::GeoIpMetadata;

/// Re-export shared atomic writer used by `GeoIP` cache + metadata saves.
pub(crate) use crate::utils::cache::write_atomic;

/// Extracts metadata from a `GeoIP` database
pub(crate) fn extract_metadata<T: AsRef<[u8]>>(reader: &Reader<T>, source: &str) -> GeoIpMetadata {
    // Try to get build epoch from database metadata
    // MaxMind databases have a build_epoch field in their metadata
    let version = format!("build_{}", reader.metadata().build_epoch);

    GeoIpMetadata {
        source: source.to_string(),
        version,
        last_updated: SystemTime::now(),
    }
}

/// Loads metadata from cache file
pub(crate) async fn load_metadata(metadata_file: &Path) -> Result<GeoIpMetadata> {
    let content = tokio::fs::read_to_string(metadata_file).await?;
    let metadata: GeoIpMetadata = serde_json::from_str(&content)?;
    Ok(metadata)
}

/// Best-effort removal of orphaned atomic-write staging files (`.{name}.tmp`).
///
/// A crash between writing the temp file and renaming it can leave these behind
/// in the `geoip/` cache directory.
pub(crate) async fn cleanup_geoip_tmp_orphans(cache_dir: &Path) {
    let Ok(mut entries) = tokio::fs::read_dir(cache_dir).await else {
        return;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !(name.starts_with('.') && name.ends_with(".tmp")) {
            continue;
        }
        match tokio::fs::remove_file(&path).await {
            Ok(()) => log::debug!("Removed orphaned GeoIP staging file {}", path.display()),
            Err(e) => log::warn!(
                "Failed to remove orphaned GeoIP staging file {}: {e}",
                path.display()
            ),
        }
    }
}

/// Saves metadata to cache file
pub(crate) async fn save_metadata(metadata: &GeoIpMetadata, metadata_file: &Path) -> Result<()> {
    let content = serde_json::to_string_pretty(metadata)?;
    write_atomic(metadata_file, content.as_bytes()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn sample_metadata() -> GeoIpMetadata {
        GeoIpMetadata {
            source: "test.mmdb".to_string(),
            version: "build_12345".to_string(),
            last_updated: SystemTime::now(),
        }
    }

    #[tokio::test]
    async fn test_load_metadata_file_not_found() {
        let metadata_file = PathBuf::from("nonexistent").join("metadata.json");
        assert!(load_metadata(&metadata_file).await.is_err());
    }

    #[tokio::test]
    async fn test_load_metadata_invalid_json() {
        let temp_dir = TempDir::new().expect("temp dir");
        let metadata_file = temp_dir.path().join("invalid.json");
        tokio::fs::write(&metadata_file, b"{ invalid json }")
            .await
            .expect("write");
        assert!(load_metadata(&metadata_file).await.is_err());

        tokio::fs::write(&metadata_file, b"{}")
            .await
            .expect("write");
        assert!(
            load_metadata(&metadata_file).await.is_err(),
            "required GeoIpMetadata fields must be present"
        );
    }

    #[tokio::test]
    async fn test_metadata_round_trip() {
        let temp_dir = TempDir::new().expect("temp dir");
        let metadata_file = temp_dir.path().join("roundtrip.json");
        let original = sample_metadata();
        save_metadata(&original, &metadata_file)
            .await
            .expect("save");
        let loaded = load_metadata(&metadata_file).await.expect("load");
        assert_eq!(loaded.source, original.source);
        assert_eq!(loaded.version, original.version);
    }

    #[tokio::test]
    async fn test_save_metadata_parent_is_file() {
        let temp_dir = TempDir::new().expect("temp dir");
        let file_path = temp_dir.path().join("not_a_directory");
        tokio::fs::write(&file_path, b"occupied")
            .await
            .expect("write");
        let metadata_file = file_path.join("metadata.json");
        assert!(save_metadata(&sample_metadata(), &metadata_file)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_cleanup_geoip_tmp_orphans_removes_staging_files() {
        let temp_dir = TempDir::new().expect("temp dir");
        let cache_dir = temp_dir.path();
        let orphan = cache_dir.join(".GeoLite2-City.mmdb.tmp");
        let keep = cache_dir.join("GeoLite2-City.mmdb");
        tokio::fs::write(&orphan, b"partial")
            .await
            .expect("write orphan");
        tokio::fs::write(&keep, b"keep").await.expect("write keep");

        cleanup_geoip_tmp_orphans(cache_dir).await;

        assert!(!orphan.exists(), "orphan .tmp should be removed");
        assert!(keep.exists(), "real MMDB should remain");
    }
}
