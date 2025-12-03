//! Fingerprint ruleset loading and caching.
//!
//! This module handles:
//! - Fetching fingerprint rulesets from URLs or local paths
//! - Merging rulesets from multiple sources
//! - Caching rulesets locally with expiration
//! - Loading categories and metadata

mod cache;
mod categories;
mod fetch;
mod github;
mod local;

use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::SystemTime;
use tokio::sync::RwLock;

use crate::fingerprint::models::{FingerprintMetadata, FingerprintRuleset};

use cache::{load_from_cache, save_to_cache};
use categories::{fetch_categories_from_url, load_categories_from_path};
use fetch::fetch_from_url;
use github::get_latest_commit_sha;
use local::load_from_path;

/// Default URLs for fingerprint sources (merged, matching Go implementation)
/// The Go implementation fetches from both sources and merges them
const DEFAULT_FINGERPRINTS_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies",
    "https://raw.githubusercontent.com/HTTPArchive/wappalyzer/main/src/technologies",
];

/// Default cache directory for fingerprint rules
const DEFAULT_CACHE_DIR: &str = ".fingerprints_cache";

/// Global ruleset cache (lazy-loaded)
static RULESET: LazyLock<Arc<RwLock<Option<Arc<FingerprintRuleset>>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(None)));

/// Initializes the fingerprint ruleset from URL or local path.
///
/// Rules are cached locally and refreshed if older than 7 days.
/// If `fingerprints_source` is None, uses the default HTTP Archive URL.
pub async fn init_ruleset(
    fingerprints_source: Option<&str>,
    cache_dir: Option<&Path>,
) -> Result<Arc<FingerprintRuleset>> {
    // Check if already loaded
    {
        let ruleset = RULESET.read().await;
        if let Some(ref cached) = *ruleset {
            return Ok(cached.clone());
        }
    }

    let sources = if let Some(source) = fingerprints_source {
        vec![source.to_string()]
    } else {
        // Use default sources (both enthec and HTTPArchive)
        DEFAULT_FINGERPRINTS_URLS
            .iter()
            .map(|s| s.to_string())
            .collect()
    };

    let cache_path = cache_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CACHE_DIR));

    // Create a cache key from all sources
    let cache_key = if sources.len() == 1 {
        sources[0].clone()
    } else {
        format!("merged:{}", sources.join("+"))
    };

    // Try to load from cache first
    if let Ok(ruleset) = load_from_cache(&cache_path, &cache_key).await {
        log::info!(
            "Loaded fingerprint ruleset from cache ({} sources)",
            sources.len()
        );
        let ruleset_arc = Arc::new(ruleset);
        *RULESET.write().await = Some(ruleset_arc.clone());
        return Ok(ruleset_arc);
    }

    // Fetch from all sources and merge
    log::info!(
        "Fetching fingerprint ruleset from {} source(s)",
        sources.len()
    );
    let ruleset = fetch_ruleset_from_multiple_sources(&sources, &cache_path).await?;
    let ruleset_arc = Arc::new(ruleset);
    *RULESET.write().await = Some(ruleset_arc.clone());
    Ok(ruleset_arc)
}

/// Gets the current ruleset metadata (for storing in database)
#[allow(dead_code)]
pub async fn get_ruleset_metadata() -> Option<FingerprintMetadata> {
    // Clone the Arc immediately to release the lock
    let ruleset = {
        let guard = RULESET.read().await;
        guard.as_ref()?.clone()
    };
    Some(ruleset.metadata.clone())
}

/// Gets the current ruleset (for use in detection)
pub(crate) async fn get_ruleset() -> Option<Arc<FingerprintRuleset>> {
    let guard = RULESET.read().await;
    guard.as_ref().cloned()
}

/// Fetches ruleset from multiple sources and merges them (matching Go implementation)
async fn fetch_ruleset_from_multiple_sources(
    sources: &[String],
    cache_dir: &Path,
) -> Result<FingerprintRuleset> {
    let mut all_technologies = HashMap::new();
    let mut all_categories = HashMap::new();
    let mut versions = Vec::new();

    // Fetch from all sources and merge
    for source in sources {
        log::info!("Fetching from source: {}", source);

        let technologies = if source.starts_with("http://") || source.starts_with("https://") {
            fetch_from_url(source).await?
        } else {
            load_from_path(Path::new(source)).await?
        };

        // Merge technologies (later sources overwrite earlier ones for same tech name)
        // This matches the Go implementation behavior
        // Normalize header and cookie keys/values to lowercase (matching Go implementation)
        for (tech_name, mut tech) in technologies {
            // Normalize header keys and patterns to lowercase (matching Go: strings.ToLower(header), strings.ToLower(pattern))
            let mut normalized_headers = HashMap::new();
            for (header_name, pattern) in tech.headers {
                normalized_headers.insert(header_name.to_lowercase(), pattern.to_lowercase());
            }
            tech.headers = normalized_headers;

            // Normalize cookie keys and patterns to lowercase (matching Go: strings.ToLower(cookie), strings.ToLower(value))
            let mut normalized_cookies = HashMap::new();
            for (cookie_name, pattern) in tech.cookies {
                normalized_cookies.insert(cookie_name.to_lowercase(), pattern.to_lowercase());
            }
            tech.cookies = normalized_cookies;

            all_technologies.insert(tech_name, tech);
        }

        // Fetch categories from this source
        let categories = if source.starts_with("http://") || source.starts_with("https://") {
            fetch_categories_from_url(source).await.unwrap_or_else(|e| {
                log::warn!(
                    "Failed to fetch categories from {}: {}. Continuing without categories from this source.",
                    source, e
                );
                HashMap::new()
            })
        } else {
            load_categories_from_path(Path::new(source))
                .await
                .unwrap_or_else(|e| {
                    log::warn!(
                        "Failed to load categories from path {}: {}. Continuing without categories from this source.",
                        source, e
                    );
                    HashMap::new()
                })
        };

        // Merge categories (later sources overwrite earlier ones)
        for (cat_id, cat_name) in categories {
            all_categories.insert(cat_id, cat_name);
        }

        // Get version from this source
        let is_github =
            source.contains("github.com") || source.contains("raw.githubusercontent.com");
        if is_github {
            if let Some(sha) = get_latest_commit_sha(source).await {
                versions.push(format!("{}:{}", source, sha));
            }
        }
    }

    let version = if versions.is_empty() {
        "unknown".to_string()
    } else {
        versions.join(";")
    };

    let source_str = sources.join("+");
    let metadata = FingerprintMetadata {
        source: source_str.clone(),
        version,
        last_updated: SystemTime::now(),
    };

    log::info!(
        "Merged {} technologies from {} source(s)",
        all_technologies.len(),
        sources.len()
    );

    let ruleset = FingerprintRuleset {
        technologies: all_technologies,
        categories: all_categories,
        metadata,
    };

    // Cache it with the merged source key
    save_to_cache(&ruleset, cache_dir).await?;

    Ok(ruleset)
}
