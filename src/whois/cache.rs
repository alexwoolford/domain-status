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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};
    use tempfile::TempDir;

    fn create_test_whois_result() -> WhoisResult {
        WhoisResult {
            creation_date: Some(chrono::Utc::now()),
            expiration_date: Some(chrono::Utc::now() + chrono::Duration::days(365)),
            updated_date: Some(chrono::Utc::now()),
            registrar: Some("Test Registrar".to_string()),
            registrant_country: Some("US".to_string()),
            registrant_org: Some("Test Org".to_string()),
            status: Some(vec!["clientTransferProhibited".to_string()]),
            nameservers: Some(vec![
                "ns1.example.com".to_string(),
                "ns2.example.com".to_string(),
            ]),
            raw_text: Some("Raw WHOIS text".to_string()),
        }
    }

    #[test]
    fn test_save_to_cache() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";
        let result = create_test_whois_result();

        // Should succeed
        assert!(save_to_cache(cache_path, domain, &result).is_ok());

        // Verify file was created
        let cache_file = cache_path.join("example_com.json");
        assert!(cache_file.exists(), "Cache file should be created");
    }

    #[test]
    fn test_load_from_cache_not_found() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "nonexistent.com";

        // Should return None for non-existent cache
        let result = load_from_cache(cache_path, domain).expect("Should not error");
        assert!(
            result.is_none(),
            "Should return None for non-existent cache"
        );
    }

    #[test]
    fn test_load_from_cache_found() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";
        let result = create_test_whois_result();

        // Save to cache first
        save_to_cache(cache_path, domain, &result).expect("Should save to cache");

        // Load from cache
        let cached = load_from_cache(cache_path, domain).expect("Should load from cache");
        assert!(cached.is_some(), "Should find cached entry");

        let entry = cached.unwrap();
        assert_eq!(entry.domain, domain);

        // Convert to WhoisResult to verify data integrity
        let whois_result: WhoisResult = entry.result.into();
        assert!(whois_result.creation_date.is_some());
        assert_eq!(whois_result.registrar, Some("Test Registrar".to_string()));
    }

    #[test]
    fn test_load_from_cache_expired() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";
        let result = create_test_whois_result();

        // Save to cache
        save_to_cache(cache_path, domain, &result).expect("Should save to cache");

        // Manually create an expired cache entry
        let cache_file = cache_path.join("example_com.json");
        let expired_entry = WhoisCacheEntry {
            result: (&result).into(),
            cached_at: SystemTime::now() - Duration::from_secs(CACHE_TTL_SECS + 1), // Expired
            domain: domain.to_string(),
        };
        let content = serde_json::to_string_pretty(&expired_entry).expect("Should serialize");
        std::fs::write(&cache_file, content).expect("Should write file");

        // Load should return None and delete expired cache
        let cached = load_from_cache(cache_path, domain).expect("Should handle expired cache");
        assert!(cached.is_none(), "Should return None for expired cache");
        assert!(!cache_file.exists(), "Expired cache file should be deleted");
    }

    #[test]
    fn test_cache_domain_name_sanitization() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";
        let result = create_test_whois_result();

        // Save to cache
        save_to_cache(cache_path, domain, &result).expect("Should save to cache");

        // Verify file name uses underscores instead of dots
        let cache_file = cache_path.join("example_com.json");
        assert!(cache_file.exists(), "Cache file should use sanitized name");
    }

    #[test]
    fn test_cache_invalid_json() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let cache_path = temp_dir.path();
        let domain = "example.com";

        // Create invalid JSON file
        let cache_file = cache_path.join("example_com.json");
        std::fs::create_dir_all(cache_path).expect("Should create directory");
        std::fs::write(&cache_file, "invalid json").expect("Should write file");

        // Load should return error
        let result = load_from_cache(cache_path, domain);
        assert!(result.is_err(), "Should error on invalid JSON");
    }
}
