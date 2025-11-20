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
