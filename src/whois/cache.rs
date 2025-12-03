//! WHOIS cache management.

use anyhow::{Context, Result};
use std::path::Path;
use std::time::SystemTime;

use super::types::{WhoisCacheEntry, WhoisResult};

/// Default cache TTL: 7 days (WHOIS data changes infrequently)
pub(crate) const CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Loads a cached WHOIS result from disk
pub(crate) fn load_from_cache(cache_path: &Path, domain: &str) -> Result<Option<WhoisCacheEntry>> {
    let cache_file = cache_path.join(format!("{}.json", domain.replace('.', "_")));

    if !cache_file.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(&cache_file).context("Failed to read cache file")?;
    let entry: WhoisCacheEntry =
        serde_json::from_str(&content).context("Failed to parse cache file")?;

    // Check if cache is still valid
    let age = entry.cached_at.elapsed().unwrap_or_default();
    if age.as_secs() > CACHE_TTL_SECS {
        // Cache expired, delete it
        let _ = std::fs::remove_file(&cache_file);
        return Ok(None);
    }

    Ok(Some(entry))
}

/// Saves a WHOIS result to disk cache
pub(crate) fn save_to_cache(cache_path: &Path, domain: &str, result: &WhoisResult) -> Result<()> {
    std::fs::create_dir_all(cache_path).context("Failed to create cache directory")?;

    let cache_file = cache_path.join(format!("{}.json", domain.replace('.', "_")));
    let entry = WhoisCacheEntry {
        result: result.into(),
        cached_at: SystemTime::now(),
        domain: domain.to_string(),
    };

    let content =
        serde_json::to_string_pretty(&entry).context("Failed to serialize cache entry")?;
    std::fs::write(&cache_file, content).context("Failed to write cache file")?;

    Ok(())
}
