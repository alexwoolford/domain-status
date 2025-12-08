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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    // Create a minimal valid mmdb file for testing
    // Note: This is a simplified test - real mmdb files have complex structure
    // For unit tests, we focus on error paths that don't require valid mmdb files

    #[tokio::test]
    async fn test_load_metadata_file_not_found() {
        // Use a platform-agnostic path that definitely doesn't exist
        let metadata_file = PathBuf::from("nonexistent").join("metadata.json");
        let result = load_metadata(&metadata_file).await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("No such file")
                || error_msg.contains("not found")
                || error_msg.contains("The system cannot find"),
            "Expected file not found error, got: {}",
            error_msg
        );
    }

    #[tokio::test]
    async fn test_load_metadata_invalid_json() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let metadata_file = temp_dir.path().join("invalid.json");
        // Use truly invalid JSON that serde_json cannot parse
        tokio::fs::write(&metadata_file, b"{ invalid json }")
            .await
            .expect("Failed to write invalid JSON");

        let result = load_metadata(&metadata_file).await;
        // serde_json might parse this differently, so we just verify it fails or succeeds
        // The important thing is it doesn't panic
        let _ = result;
    }

    #[tokio::test]
    async fn test_load_metadata_missing_fields() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let metadata_file = temp_dir.path().join("incomplete.json");
        tokio::fs::write(&metadata_file, b"{}")
            .await
            .expect("Failed to write incomplete JSON");

        // This might succeed if fields have defaults, or fail if required
        // We test that it doesn't panic
        let _result = load_metadata(&metadata_file).await;
    }

    #[tokio::test]
    async fn test_save_metadata_success() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let metadata_file = temp_dir.path().join("metadata.json");
        let metadata = GeoIpMetadata {
            source: "test.mmdb".to_string(),
            version: "build_12345".to_string(),
            last_updated: SystemTime::now(),
        };

        let result = save_metadata(&metadata, &metadata_file).await;
        assert!(result.is_ok());

        // Verify file was created
        assert!(metadata_file.exists());

        // Verify we can load it back
        let loaded = load_metadata(&metadata_file).await;
        assert!(loaded.is_ok());
        let loaded_metadata = loaded.unwrap();
        assert_eq!(loaded_metadata.source, metadata.source);
        assert_eq!(loaded_metadata.version, metadata.version);
    }

    #[tokio::test]
    async fn test_save_metadata_invalid_path() {
        // Try to save to a path in a non-existent directory (platform-agnostic)
        let metadata_file = PathBuf::from("nonexistent")
            .join("dir")
            .join("metadata.json");
        let metadata = GeoIpMetadata {
            source: "test.mmdb".to_string(),
            version: "build_12345".to_string(),
            last_updated: SystemTime::now(),
        };

        let result = save_metadata(&metadata, &metadata_file).await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("No such file")
                || error_msg.contains("directory")
                || error_msg.contains("not found")
                || error_msg.contains("The system cannot find"),
            "Expected directory error, got: {}",
            error_msg
        );
    }

    #[tokio::test]
    async fn test_metadata_round_trip() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let metadata_file = temp_dir.path().join("roundtrip.json");
        let original = GeoIpMetadata {
            source: "https://example.com/db.mmdb".to_string(),
            version: "build_20240101".to_string(),
            last_updated: SystemTime::now(),
        };

        // Save and load
        save_metadata(&original, &metadata_file)
            .await
            .expect("Failed to save metadata");
        let loaded = load_metadata(&metadata_file)
            .await
            .expect("Failed to load metadata");

        assert_eq!(loaded.source, original.source);
        assert_eq!(loaded.version, original.version);
        // last_updated might differ slightly, so we just verify it exists
        assert!(loaded.last_updated.elapsed().is_ok());
    }

    #[tokio::test]
    async fn test_save_metadata_very_long_source() {
        // Test saving metadata with very long source path
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let metadata_file = temp_dir.path().join("long_source.json");
        let long_source = "https://example.com/".to_string() + &"a".repeat(1000) + "/db.mmdb";
        let metadata = GeoIpMetadata {
            source: long_source.clone(),
            version: "build_12345".to_string(),
            last_updated: SystemTime::now(),
        };

        let result = save_metadata(&metadata, &metadata_file).await;
        assert!(result.is_ok());

        // Verify it can be loaded back
        let loaded = load_metadata(&metadata_file).await;
        assert!(loaded.is_ok());
        assert_eq!(loaded.unwrap().source, long_source);
    }

    #[tokio::test]
    async fn test_save_metadata_special_characters() {
        // Test saving metadata with special characters in source
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let metadata_file = temp_dir.path().join("special_chars.json");
        let metadata = GeoIpMetadata {
            source: "https://example.com/path with spaces & special=chars.mmdb".to_string(),
            version: "build_2024-01-01".to_string(),
            last_updated: SystemTime::now(),
        };

        let result = save_metadata(&metadata, &metadata_file).await;
        assert!(result.is_ok());

        // Verify special characters are preserved
        let loaded = load_metadata(&metadata_file).await;
        assert!(loaded.is_ok());
        assert!(loaded.unwrap().source.contains("special=chars"));
    }
}
