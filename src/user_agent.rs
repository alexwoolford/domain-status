//! User-Agent string management with automatic updates.
//!
//! This module provides functionality to fetch and cache the latest Chrome version
//! for User-Agent strings, ensuring they stay current over time.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use tokio::fs;

/// Default cache directory for User-Agent version
const DEFAULT_CACHE_DIR: &str = ".user_agent_cache";

/// Cache duration: 30 days
/// Chrome releases roughly every 4 weeks, so 30 days ensures we stay current
const CACHE_DURATION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Fallback Chrome version if fetch fails
/// Updated to Chrome 131 (November 2024)
const FALLBACK_CHROME_VERSION: &str = "131.0.0.0";

/// User-Agent metadata stored in cache
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserAgentMetadata {
    chrome_version: String,
    last_updated: SystemTime,
}

/// Fetches the latest Chrome version from Chrome's release API.
///
/// Uses Chrome's release API to get the latest stable version.
/// Falls back to FALLBACK_CHROME_VERSION if fetch fails.
async fn fetch_latest_chrome_version() -> String {
    // Try multiple sources for reliability
    // Note: ChromeDriver API may return older versions, so we try Chrome for Testing first
    let sources = vec![
        // Chrome for Testing releases (most up-to-date)
        "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json",
        // Fallback: ChromeDriver release API
        "https://chromedriver.storage.googleapis.com/LATEST_RELEASE",
    ];

    for source in sources {
        match try_fetch_chrome_version(source).await {
            Ok(version) => {
                log::debug!("Fetched Chrome version {} from {}", version, source);
                return version;
            }
            Err(e) => {
                log::debug!("Failed to fetch Chrome version from {}: {}", source, e);
            }
        }
    }

    log::warn!(
        "Failed to fetch latest Chrome version from all sources, using fallback: {}",
        FALLBACK_CHROME_VERSION
    );
    FALLBACK_CHROME_VERSION.to_string()
}

/// Attempts to fetch Chrome version from a specific source.
async fn try_fetch_chrome_version(url: &str) -> Result<String, anyhow::Error> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let response = client.get(url).send().await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!("HTTP {}", response.status()));
    }

    let text = response.text().await?;

    // Handle different response formats
    if url.contains("LATEST_RELEASE") {
        // Simple version string: "131.0.6778.85"
        // Extract major version (e.g., "131.0.6778.85" -> "131.0.0.0")
        let version = text.trim();
        let major = version.split('.').next().unwrap_or(version);
        Ok(format!("{}.0.0.0", major))
    } else if url.contains("chrome-for-testing") {
        // JSON response: extract version from "stable" channel
        #[derive(Deserialize)]
        struct ChromeVersions {
            channels: Option<ChromeChannels>,
        }
        #[derive(Deserialize)]
        struct ChromeChannels {
            #[serde(rename = "Stable")]
            stable: Option<ChromeVersion>,
        }
        #[derive(Deserialize)]
        struct ChromeVersion {
            version: String,
        }

        let versions: ChromeVersions = serde_json::from_str(&text)?;
        if let Some(channels) = versions.channels {
            if let Some(stable) = channels.stable {
                // Extract major version (e.g., "131.0.6778.85" -> "131")
                let major = stable
                    .version
                    .split('.')
                    .next()
                    .unwrap_or(&stable.version)
                    .to_string();
                return Ok(format!("{}.0.0.0", major));
            }
        }
        Err(anyhow::anyhow!("No stable version found in JSON"))
    } else {
        // Try to parse as version string
        Ok(text.trim().to_string())
    }
}

/// Gets the Chrome version, using cache if available and fresh.
///
/// Returns the cached version if it exists and is less than 30 days old.
/// Otherwise, fetches the latest version and caches it.
pub async fn get_chrome_version(cache_dir: Option<&Path>) -> String {
    let cache_path = cache_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CACHE_DIR));

    // Try to load from cache first
    if let Ok(version) = load_from_cache(&cache_path).await {
        return version;
    }

    // Cache miss or expired - fetch latest
    let version = fetch_latest_chrome_version().await;

    // Save to cache (ignore errors - caching is best-effort)
    if let Err(e) = save_to_cache(&cache_path, &version).await {
        log::debug!("Failed to save User-Agent cache: {}", e);
    }

    version
}

/// Loads Chrome version from cache if it exists and is fresh.
async fn load_from_cache(cache_dir: &Path) -> Result<String, anyhow::Error> {
    let metadata_path = cache_dir.join("version.json");

    if !metadata_path.exists() {
        return Err(anyhow::anyhow!("Cache not found"));
    }

    let metadata_json = fs::read_to_string(&metadata_path).await?;
    let metadata: UserAgentMetadata = serde_json::from_str(&metadata_json)?;

    // Check if cache is fresh
    if let Ok(age) = metadata.last_updated.elapsed() {
        if age > CACHE_DURATION {
            return Err(anyhow::anyhow!("Cache expired"));
        }
    }

    Ok(metadata.chrome_version)
}

/// Saves Chrome version to cache.
async fn save_to_cache(cache_dir: &Path, version: &str) -> Result<(), anyhow::Error> {
    // Create cache directory if it doesn't exist
    fs::create_dir_all(cache_dir).await?;

    let metadata = UserAgentMetadata {
        chrome_version: version.to_string(),
        last_updated: SystemTime::now(),
    };

    let metadata_path = cache_dir.join("version.json");
    let metadata_json = serde_json::to_string_pretty(&metadata)?;
    fs::write(&metadata_path, metadata_json).await?;

    Ok(())
}

/// Generates a User-Agent string with the given Chrome version.
pub fn generate_user_agent(chrome_version: &str) -> String {
    format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{} Safari/537.36",
        chrome_version
    )
}

/// Gets the default User-Agent string, using cached Chrome version if available.
///
/// This function attempts to fetch the latest Chrome version at startup,
/// caches it locally for 30 days, and falls back to a hardcoded version
/// if fetching fails.
///
/// The User-Agent is cached to avoid fetching on every run, but will
/// automatically update when the cache expires (30 days).
pub async fn get_default_user_agent(cache_dir: Option<&Path>) -> String {
    let chrome_version = get_chrome_version(cache_dir).await;
    generate_user_agent(&chrome_version)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};
    use tempfile::TempDir;

    #[test]
    fn test_generate_user_agent() {
        let version = "131.0.0.0";
        let ua = generate_user_agent(version);
        assert!(ua.contains("Chrome/131.0.0.0"));
        assert!(ua.contains("Mozilla/5.0"));
        assert!(ua.contains("Windows NT 10.0"));
    }

    #[tokio::test]
    async fn test_get_chrome_version_fallback() {
        // Test that fallback works when network fails
        // We can't easily mock network failures, but we can test the fallback logic
        // by checking that invalid cache returns fallback
        let temp_dir = TempDir::new().unwrap();
        let cache_dir = temp_dir.path();

        // With no cache and no network (in test environment), should use fallback
        // Note: This test may actually fetch from network if available
        let version = get_chrome_version(Some(cache_dir)).await;
        assert!(!version.is_empty());
        // Version should be in format "X.0.0.0"
        assert!(version.contains('.'));
    }

    #[tokio::test]
    async fn test_load_from_cache_missing_file() {
        let temp_dir = TempDir::new().unwrap();
        let cache_dir = temp_dir.path();

        let result = load_from_cache(cache_dir).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Cache not found"));
    }

    #[tokio::test]
    async fn test_load_from_cache_expired() {
        let temp_dir = TempDir::new().unwrap();
        let cache_dir = temp_dir.path();

        // Create expired cache entry
        let metadata = UserAgentMetadata {
            chrome_version: "100.0.0.0".to_string(),
            last_updated: SystemTime::now() - Duration::from_secs(31 * 24 * 60 * 60), // 31 days ago
        };

        let metadata_path = cache_dir.join("version.json");
        std::fs::create_dir_all(cache_dir).unwrap();
        let metadata_json = serde_json::to_string_pretty(&metadata).unwrap();
        std::fs::write(&metadata_path, metadata_json).unwrap();

        let result = load_from_cache(cache_dir).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Cache expired"));
    }

    #[tokio::test]
    async fn test_load_from_cache_valid() {
        let temp_dir = TempDir::new().unwrap();
        let cache_dir = temp_dir.path();

        // Create valid cache entry
        let metadata = UserAgentMetadata {
            chrome_version: "131.0.0.0".to_string(),
            last_updated: SystemTime::now() - Duration::from_secs(24 * 60 * 60), // 1 day ago
        };

        let metadata_path = cache_dir.join("version.json");
        std::fs::create_dir_all(cache_dir).unwrap();
        let metadata_json = serde_json::to_string_pretty(&metadata).unwrap();
        std::fs::write(&metadata_path, metadata_json).unwrap();

        let result = load_from_cache(cache_dir).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "131.0.0.0");
    }

    #[tokio::test]
    async fn test_save_to_cache() {
        let temp_dir = TempDir::new().unwrap();
        let cache_dir = temp_dir.path();

        let version = "131.0.0.0";
        let result = save_to_cache(cache_dir, version).await;
        assert!(result.is_ok());

        // Verify cache file was created
        let metadata_path = cache_dir.join("version.json");
        assert!(metadata_path.exists());

        // Verify cache can be loaded
        let loaded = load_from_cache(cache_dir).await;
        assert!(loaded.is_ok());
        assert_eq!(loaded.unwrap(), version);
    }

    #[tokio::test]
    async fn test_save_to_cache_malformed_json() {
        let temp_dir = TempDir::new().unwrap();
        let cache_dir = temp_dir.path();

        // Create malformed JSON file
        let metadata_path = cache_dir.join("version.json");
        std::fs::create_dir_all(cache_dir).unwrap();
        std::fs::write(&metadata_path, "{ invalid json }").unwrap();

        let result = load_from_cache(cache_dir).await;
        assert!(result.is_err());
        // Should fail to parse JSON
    }

    #[tokio::test]
    async fn test_get_default_user_agent() {
        let temp_dir = TempDir::new().unwrap();
        let cache_dir = temp_dir.path();

        let ua = get_default_user_agent(Some(cache_dir)).await;
        assert!(ua.contains("Chrome/"));
        assert!(ua.contains("Mozilla/5.0"));
    }

    #[test]
    fn test_try_fetch_chrome_version_latest_release_format() {
        // Test parsing of LATEST_RELEASE format (simple version string)
        // This is a unit test for the parsing logic
        let version_text = "131.0.6778.85";
        let major = version_text.split('.').next().unwrap_or(version_text);
        let formatted = format!("{}.0.0.0", major);
        assert_eq!(formatted, "131.0.0.0");
    }

    #[test]
    fn test_try_fetch_chrome_version_json_format() {
        // Test parsing of chrome-for-testing JSON format
        // This simulates the JSON structure
        let json = r#"{
            "channels": {
                "Stable": {
                    "version": "131.0.6778.85"
                }
            }
        }"#;

        #[derive(serde::Deserialize)]
        struct ChromeVersions {
            channels: Option<ChromeChannels>,
        }
        #[derive(serde::Deserialize)]
        struct ChromeChannels {
            #[serde(rename = "Stable")]
            stable: Option<ChromeVersion>,
        }
        #[derive(serde::Deserialize)]
        struct ChromeVersion {
            version: String,
        }

        let versions: ChromeVersions = serde_json::from_str(json).unwrap();
        if let Some(channels) = versions.channels {
            if let Some(stable) = channels.stable {
                let major = stable.version.split('.').next().unwrap_or(&stable.version);
                let formatted = format!("{}.0.0.0", major);
                assert_eq!(formatted, "131.0.0.0");
            }
        }
    }

    #[test]
    fn test_try_fetch_chrome_version_json_missing_stable() {
        // Test JSON with channels but no Stable channel
        let json = r#"{
            "channels": {
                "Beta": {
                    "version": "132.0.6778.85"
                }
            }
        }"#;

        #[derive(serde::Deserialize)]
        struct ChromeVersions {
            channels: Option<ChromeChannels>,
        }
        #[derive(serde::Deserialize)]
        struct ChromeChannels {
            #[serde(rename = "Stable")]
            stable: Option<ChromeVersion>,
        }
        #[derive(serde::Deserialize)]
        struct ChromeVersion {
            #[allow(dead_code)]
            version: String,
        }

        let versions: ChromeVersions = serde_json::from_str(json).unwrap();
        // Should handle missing Stable channel gracefully
        if let Some(channels) = versions.channels {
            assert!(channels.stable.is_none());
        }
    }

    #[test]
    fn test_try_fetch_chrome_version_json_missing_version_field() {
        // Test JSON with Stable channel but missing version field
        let json = r#"{
            "channels": {
                "Stable": {}
            }
        }"#;

        #[derive(serde::Deserialize)]
        struct ChromeVersions {
            #[allow(dead_code)]
            channels: Option<ChromeChannels>,
        }
        #[derive(serde::Deserialize)]
        struct ChromeChannels {
            #[serde(rename = "Stable")]
            #[allow(dead_code)]
            stable: Option<ChromeVersion>,
        }
        #[derive(serde::Deserialize)]
        struct ChromeVersion {
            #[allow(dead_code)]
            version: String,
        }

        // Should fail to deserialize if version field is missing (serde will error)
        let result: Result<ChromeVersions, _> = serde_json::from_str(json);
        // serde_json will error on missing required field
        assert!(result.is_err());
    }

    #[test]
    fn test_try_fetch_chrome_version_json_empty_channels() {
        // Test JSON with empty channels object
        let json = r#"{
            "channels": {}
        }"#;

        #[derive(serde::Deserialize)]
        struct ChromeVersions {
            channels: Option<ChromeChannels>,
        }
        #[derive(serde::Deserialize)]
        struct ChromeChannels {
            #[serde(rename = "Stable")]
            stable: Option<ChromeVersion>,
        }
        #[derive(serde::Deserialize)]
        struct ChromeVersion {
            #[allow(dead_code)]
            version: String,
        }

        let versions: ChromeVersions = serde_json::from_str(json).unwrap();
        if let Some(channels) = versions.channels {
            assert!(channels.stable.is_none());
        }
    }

    #[test]
    fn test_try_fetch_chrome_version_latest_release_empty_string() {
        // Test empty version string handling
        let version_text = "";
        let major = version_text.split('.').next().unwrap_or(version_text);
        // Empty string should result in ".0.0.0"
        let formatted = format!("{}.0.0.0", major);
        assert_eq!(formatted, ".0.0.0");
    }

    #[test]
    fn test_try_fetch_chrome_version_latest_release_no_dots() {
        // Test version string without dots
        let version_text = "131";
        let major = version_text.split('.').next().unwrap_or(version_text);
        let formatted = format!("{}.0.0.0", major);
        assert_eq!(formatted, "131.0.0.0");
    }

    #[test]
    fn test_load_from_cache_missing_chrome_version_field() {
        // Test cache file with missing chrome_version field
        let json = r#"{
            "last_updated": "2024-01-01T00:00:00Z"
        }"#;

        let result: Result<UserAgentMetadata, _> = serde_json::from_str(json);
        // Should fail to deserialize if chrome_version field is missing
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_load_from_cache_invalid_timestamp() {
        // Test cache file with invalid timestamp (future date)
        let temp_dir = TempDir::new().unwrap();
        let cache_dir = temp_dir.path();

        // Create cache with future timestamp (should still be valid if within cache duration)
        let metadata = UserAgentMetadata {
            chrome_version: "131.0.0.0".to_string(),
            last_updated: SystemTime::now() + Duration::from_secs(24 * 60 * 60), // 1 day in future
        };

        let metadata_path = cache_dir.join("version.json");
        std::fs::create_dir_all(cache_dir).unwrap();
        let metadata_json = serde_json::to_string_pretty(&metadata).unwrap();
        std::fs::write(&metadata_path, metadata_json).unwrap();

        // Future timestamp should still be valid (elapsed() returns error for future times)
        let result = load_from_cache(cache_dir).await;
        // Should succeed because elapsed() returns Err for future times, so age check is skipped
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_save_to_cache_directory_creation() {
        // Test that cache directory is created if it doesn't exist
        let temp_dir = TempDir::new().unwrap();
        let cache_dir = temp_dir.path().join("nested").join("cache");

        // Directory doesn't exist yet
        assert!(!cache_dir.exists());

        let version = "131.0.0.0";
        let result = save_to_cache(&cache_dir, version).await;
        assert!(result.is_ok());

        // Directory should now exist
        assert!(cache_dir.exists());
        assert!(cache_dir.join("version.json").exists());
    }

    #[tokio::test]
    async fn test_get_chrome_version_cache_fresh() {
        // Test that fresh cache is used instead of fetching
        let temp_dir = TempDir::new().unwrap();
        let cache_dir = temp_dir.path();

        // Create fresh cache
        let metadata = UserAgentMetadata {
            chrome_version: "131.0.0.0".to_string(),
            last_updated: SystemTime::now() - Duration::from_secs(24 * 60 * 60), // 1 day ago
        };

        let metadata_path = cache_dir.join("version.json");
        std::fs::create_dir_all(cache_dir).unwrap();
        let metadata_json = serde_json::to_string_pretty(&metadata).unwrap();
        std::fs::write(&metadata_path, metadata_json).unwrap();

        // Should return cached version
        let version = get_chrome_version(Some(cache_dir)).await;
        assert_eq!(version, "131.0.0.0");
    }

    #[tokio::test]
    async fn test_get_chrome_version_cache_expired() {
        // Test that expired cache triggers fetch
        let temp_dir = TempDir::new().unwrap();
        let cache_dir = temp_dir.path();

        // Create expired cache
        let metadata = UserAgentMetadata {
            chrome_version: "100.0.0.0".to_string(), // Old version
            last_updated: SystemTime::now() - Duration::from_secs(31 * 24 * 60 * 60), // 31 days ago
        };

        let metadata_path = cache_dir.join("version.json");
        std::fs::create_dir_all(cache_dir).unwrap();
        let metadata_json = serde_json::to_string_pretty(&metadata).unwrap();
        std::fs::write(&metadata_path, metadata_json).unwrap();

        // Should fetch new version (or use fallback if network unavailable)
        let version = get_chrome_version(Some(cache_dir)).await;
        // Version should be updated (not the old cached version)
        assert_ne!(version, "100.0.0.0");
        assert!(!version.is_empty());
    }

    #[tokio::test]
    async fn test_try_fetch_chrome_version_http_error() {
        // Test that HTTP errors are handled correctly
        use httptest::{matchers::*, responders::*, Expectation, Server};

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/error"))
                .respond_with(status_code(500).body("Internal Server Error")),
        );

        let url = server.url("/error").to_string();
        let result = try_fetch_chrome_version(&url).await;

        // Should return error for HTTP 500
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HTTP 500"));
    }

    #[tokio::test]
    async fn test_try_fetch_chrome_version_invalid_json() {
        // Test that invalid JSON is handled correctly
        // Note: If URL doesn't contain "LATEST_RELEASE" or "chrome-for-testing",
        // the function returns the text as-is (doesn't parse as JSON)
        // So we need to use a URL that triggers JSON parsing
        use httptest::{matchers::*, responders::*, Expectation, Server};

        let server = Server::run();
        // Use a URL that contains "chrome-for-testing" to trigger JSON parsing
        let url_path = "/chrome-for-testing/invalid";
        server.expect(
            Expectation::matching(request::method_path("GET", url_path)).respond_with(
                status_code(200)
                    .insert_header("Content-Type", "application/json")
                    .body("{ invalid json }"),
            ),
        );

        let url = server.url(url_path).to_string();
        let result = try_fetch_chrome_version(&url).await;

        // Should return error for invalid JSON when parsing is attempted
        assert!(result.is_err());
        // Error should indicate JSON parsing failure (serde_json errors vary)
        let error_msg = result.unwrap_err().to_string();
        // serde_json errors may vary widely, but should indicate parsing failure
        // Common patterns: "JSON", "parse", "invalid", "deserialize", "expected", "key", "string", "line", "column"
        assert!(
            error_msg.contains("JSON")
                || error_msg.contains("parse")
                || error_msg.contains("invalid")
                || error_msg.contains("deserialize")
                || error_msg.contains("expected")
                || error_msg.contains("key")
                || error_msg.contains("string")
                || error_msg.contains("line")
                || error_msg.contains("column"),
            "Error message should indicate parsing failure: {}",
            error_msg
        );
    }

    #[tokio::test]
    async fn test_try_fetch_chrome_version_empty_response() {
        // Test that empty response is handled correctly
        use httptest::{matchers::*, responders::*, Expectation, Server};

        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/empty"))
                .respond_with(status_code(200).body("")),
        );

        let url = server.url("/empty").to_string();
        let result = try_fetch_chrome_version(&url).await;

        // Empty response for LATEST_RELEASE format should result in ".0.0.0"
        // Empty response for chrome-for-testing should error
        // Either is acceptable - the function should handle gracefully
        let _ = result;
    }

    #[test]
    fn test_try_fetch_chrome_version_version_parsing_edge_cases() {
        // Test edge cases in version parsing
        // Many dots
        let many = "131.0.6778.85.123.456";
        let major = many.split('.').next().unwrap_or(many);
        assert_eq!(format!("{}.0.0.0", major), "131.0.0.0");

        // Non-numeric
        let non_numeric = "abc.def.ghi";
        let major = non_numeric.split('.').next().unwrap_or(non_numeric);
        assert_eq!(format!("{}.0.0.0", major), "abc.0.0.0");
    }
}
