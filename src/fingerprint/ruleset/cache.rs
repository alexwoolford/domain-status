//! Ruleset caching operations.
//!
//! This module handles loading and saving fingerprint rulesets to/from local cache.

use anyhow::Result;
use std::path::Path;
use tokio::fs;

use crate::fingerprint::models::{FingerprintMetadata, FingerprintRuleset};

/// Cache duration: 7 days
/// Based on commit history, HTTP Archive updates technologies roughly weekly
const CACHE_DURATION: std::time::Duration =
    std::time::Duration::from_secs(crate::config::FINGERPRINT_CACHE_TTL_SECS);

/// Loads ruleset from cache if it exists and is fresh
pub(crate) async fn load_from_cache(cache_dir: &Path, source: &str) -> Result<FingerprintRuleset> {
    let metadata_path = cache_dir.join("metadata.json");
    let technologies_path = cache_dir.join("technologies.json");
    let categories_path = cache_dir.join("categories.json");

    // Check if cache exists
    if !metadata_path.exists() || !technologies_path.exists() {
        return Err(anyhow::anyhow!("Cache not found"));
    }

    // Load metadata
    let metadata_json = fs::read_to_string(&metadata_path).await?;
    let metadata: FingerprintMetadata = serde_json::from_str(&metadata_json)?;

    // Check if cache is for the same source(s)
    // Handle both single source and merged sources (format: "merged:url1+url2")
    if metadata.source != source {
        // If source is a merged key, check if it matches the metadata source
        // If metadata source is also merged, they should match exactly
        // If source is a single URL but metadata is merged, that's a mismatch
        if source.starts_with("merged:") || metadata.source.starts_with("merged:") {
            // Both are merged keys - must match exactly
            if metadata.source != source {
                return Err(anyhow::anyhow!(
                    "Cache source mismatch: expected '{}', got '{}'",
                    source,
                    metadata.source
                ));
            }
        } else {
            // Single source mismatch
            return Err(anyhow::anyhow!(
                "Cache source mismatch: expected '{}', got '{}'",
                source,
                metadata.source
            ));
        }
    }

    // Check if cache is fresh
    if let Ok(age) = metadata.last_updated.elapsed() {
        if age > CACHE_DURATION {
            return Err(anyhow::anyhow!("Cache expired"));
        }
    }

    // Load technologies
    let technologies_json = fs::read_to_string(&technologies_path).await?;
    let technologies: std::collections::HashMap<String, crate::fingerprint::models::Technology> =
        serde_json::from_str(&technologies_json)?;

    // Load categories (optional - may not exist in cache)
    let categories = if categories_path.exists() {
        match fs::read_to_string(&categories_path).await {
            Ok(categories_json) => {
                match serde_json::from_str::<std::collections::HashMap<u32, String>>(
                    &categories_json,
                ) {
                    Ok(cats) => {
                        log::debug!("Loaded {} categories from cache", cats.len());
                        cats
                    }
                    Err(e) => {
                        log::warn!("Failed to parse categories from cache: {}", e);
                        std::collections::HashMap::new()
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to read categories from cache: {}", e);
                std::collections::HashMap::new()
            }
        }
    } else {
        log::debug!("Categories cache not found, using empty map");
        std::collections::HashMap::new()
    };

    Ok(FingerprintRuleset {
        technologies,
        categories,
        metadata,
    })
}

/// Saves ruleset to cache
pub(crate) async fn save_to_cache(ruleset: &FingerprintRuleset, cache_dir: &Path) -> Result<()> {
    fs::create_dir_all(cache_dir).await?;

    let metadata_path = cache_dir.join("metadata.json");
    let technologies_path = cache_dir.join("technologies.json");
    let categories_path = cache_dir.join("categories.json");

    // Save metadata
    let metadata_json = serde_json::to_string_pretty(&ruleset.metadata)?;
    fs::write(&metadata_path, metadata_json).await?;

    // Save technologies
    let technologies_json = serde_json::to_string_pretty(&ruleset.technologies)?;
    fs::write(&technologies_path, technologies_json).await?;

    // Save categories
    let categories_json = serde_json::to_string_pretty(&ruleset.categories)?;
    fs::write(&categories_path, categories_json).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;
    use tempfile::TempDir;

    fn create_test_ruleset(source: &str) -> FingerprintRuleset {
        FingerprintRuleset {
            technologies: std::collections::HashMap::new(),
            categories: std::collections::HashMap::new(),
            metadata: FingerprintMetadata {
                source: source.to_string(),
                version: "test".to_string(),
                last_updated: SystemTime::now(),
            },
        }
    }

    #[tokio::test]
    async fn test_load_from_cache_not_found() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let result = load_from_cache(temp_dir.path(), "test-source").await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Cache not found"),
            "Expected cache not found error, got: {}",
            error_msg
        );
    }

    #[tokio::test]
    async fn test_load_from_cache_source_mismatch() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_dir = temp_dir.path();

        // Save cache with one source
        let ruleset = create_test_ruleset("source1");
        save_to_cache(&ruleset, cache_dir)
            .await
            .expect("Failed to save cache");

        // Try to load with different source
        let result = load_from_cache(cache_dir, "source2").await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("source mismatch"),
            "Expected source mismatch error, got: {}",
            error_msg
        );
    }

    #[tokio::test]
    async fn test_load_from_cache_expired() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_dir = temp_dir.path();

        // Create expired metadata
        let expired_metadata = FingerprintMetadata {
            source: "test-source".to_string(),
            version: "test".to_string(),
            last_updated: SystemTime::now() - std::time::Duration::from_secs(7 * 24 * 60 * 60 + 1), // Expired
        };

        // Save expired cache
        let metadata_path = cache_dir.join("metadata.json");
        let metadata_json = serde_json::to_string_pretty(&expired_metadata).unwrap();
        tokio::fs::write(&metadata_path, metadata_json)
            .await
            .expect("Failed to write metadata");

        // Create technologies file (required for cache to exist)
        let technologies_path = cache_dir.join("technologies.json");
        tokio::fs::write(&technologies_path, "{}")
            .await
            .expect("Failed to write technologies");

        let result = load_from_cache(cache_dir, "test-source").await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("expired"),
            "Expected expired cache error, got: {}",
            error_msg
        );
    }

    #[tokio::test]
    async fn test_save_and_load_from_cache_round_trip() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_dir = temp_dir.path();

        let ruleset = create_test_ruleset("test-source");
        save_to_cache(&ruleset, cache_dir)
            .await
            .expect("Failed to save cache");

        let loaded = load_from_cache(cache_dir, "test-source")
            .await
            .expect("Failed to load cache");

        assert_eq!(loaded.metadata.source, ruleset.metadata.source);
        assert_eq!(loaded.metadata.version, ruleset.metadata.version);
    }

    #[tokio::test]
    async fn test_load_from_cache_missing_categories() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_dir = temp_dir.path();

        // Save cache without categories file
        let ruleset = create_test_ruleset("test-source");
        save_to_cache(&ruleset, cache_dir)
            .await
            .expect("Failed to save cache");

        // Delete categories file
        let categories_path = cache_dir.join("categories.json");
        let _ = tokio::fs::remove_file(&categories_path).await;

        // Should still load successfully (categories are optional)
        let loaded = load_from_cache(cache_dir, "test-source")
            .await
            .expect("Failed to load cache");
        assert!(loaded.categories.is_empty());
    }

    #[tokio::test]
    async fn test_load_from_cache_invalid_metadata_json() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_dir = temp_dir.path();

        // Create invalid metadata file
        let metadata_path = cache_dir.join("metadata.json");
        tokio::fs::write(&metadata_path, b"{ invalid json }")
            .await
            .expect("Failed to write invalid metadata");

        // Create technologies file (required for cache to exist)
        let technologies_path = cache_dir.join("technologies.json");
        tokio::fs::write(&technologies_path, "{}")
            .await
            .expect("Failed to write technologies");

        let result = load_from_cache(cache_dir, "test-source").await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("parse")
                || error_msg.contains("JSON")
                || error_msg.contains("key must be a string")
                || error_msg.contains("invalid"),
            "Expected JSON parse error, got: {}",
            error_msg
        );
    }

    #[tokio::test]
    async fn test_load_from_cache_merged_source() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_dir = temp_dir.path();

        // Save cache with merged source
        let ruleset = create_test_ruleset("merged:url1+url2");
        save_to_cache(&ruleset, cache_dir)
            .await
            .expect("Failed to save cache");

        // Load with matching merged source
        let loaded = load_from_cache(cache_dir, "merged:url1+url2")
            .await
            .expect("Failed to load cache");
        assert_eq!(loaded.metadata.source, "merged:url1+url2");
    }

    #[tokio::test]
    async fn test_save_to_cache_creates_directory() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_dir = temp_dir.path().join("nested").join("cache");

        let ruleset = create_test_ruleset("test-source");
        let result = save_to_cache(&ruleset, &cache_dir).await;
        assert!(result.is_ok());

        // Verify files were created
        assert!(cache_dir.join("metadata.json").exists());
        assert!(cache_dir.join("technologies.json").exists());
        assert!(cache_dir.join("categories.json").exists());
    }
}
