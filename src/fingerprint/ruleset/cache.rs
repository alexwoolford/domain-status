//! Ruleset caching operations.
//!
//! This module handles loading and saving fingerprint rulesets to/from local cache.

use anyhow::Result;
use std::path::Path;
use tokio::fs;

use crate::fingerprint::models::{FingerprintMetadata, FingerprintRuleset};

/// Cache duration: 7 days
/// Based on commit history, HTTP Archive updates technologies roughly weekly
const CACHE_DURATION: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 60 * 60);

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
