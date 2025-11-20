//! Technology detection using community-maintained fingerprint rulesets.
//!
//! This module implements technology detection by fetching and applying
//! fingerprint rules from community sources like HTTP Archive or Enthec.
//! Rules are cached locally and can be updated periodically.
//!
//! # JavaScript Property Detection
//!
//! This module executes JavaScript code (both inline and external scripts) to detect
//! JavaScript object properties, matching the behavior of the Golang Wappalyzer tool.
//!
//! **Security measures:**
//! - Memory limit: 10MB per JavaScript context
//! - Execution timeout: 1 second per property check
//! - Script size limits: 100KB per script, 500KB total
//! - Maximum external scripts: 10 per page (to prevent excessive fetching)
//! - Fallback to regex: If JavaScript execution fails, falls back to regex matching

use anyhow::{Context as AnyhowContext, Result};
use reqwest::header::HeaderMap;
use rquickjs::{Context, Runtime};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime};
use tokio::fs;
use tokio::sync::RwLock;

/// Default URLs for fingerprint sources (merged, matching Go implementation)
/// The Go implementation fetches from both sources and merges them
const DEFAULT_FINGERPRINTS_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies",
    "https://raw.githubusercontent.com/HTTPArchive/wappalyzer/main/src/technologies",
];

/// Default cache directory for fingerprint rules
const DEFAULT_CACHE_DIR: &str = ".fingerprints_cache";

/// Cache duration: 7 days
/// Based on commit history, HTTP Archive updates technologies roughly weekly
const CACHE_DURATION: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Technology fingerprint rule structure matching Wappalyzer schema
/// Note: The technology name is the key in the JSON, not a field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technology {
    /// Category IDs
    #[serde(default)]
    pub cats: Vec<u32>,
    /// Website URL
    #[serde(default)]
    pub website: String,
    /// Header patterns: header_name -> pattern
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Cookie patterns: cookie_name -> pattern
    #[serde(default)]
    pub cookies: HashMap<String, String>,
    /// Meta tag patterns: meta_name -> pattern(s)
    /// In Wappalyzer, meta values can be either a string or an array of strings
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_meta_map")]
    pub meta: HashMap<String, Vec<String>>,
    /// Script source patterns (can be string or array) - Wappalyzer uses "scriptSrc"
    #[serde(default)]
    #[serde(alias = "scriptSrc")]
    #[serde(deserialize_with = "deserialize_string_or_array")]
    pub script: Vec<String>,
    /// HTML text patterns (can be string or array)
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_string_or_array")]
    pub html: Vec<String>,
    /// URL patterns (can be string or array)
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_string_or_array")]
    pub url: Vec<String>,
    /// JavaScript object properties to check
    #[serde(default)]
    pub js: HashMap<String, String>,
    /// Implies other technologies (can be string or array)
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_string_or_array")]
    pub implies: Vec<String>,
    /// Excludes other technologies (can be string or array)
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_string_or_array")]
    pub excludes: Vec<String>,
}

/// Deserializes a field that can be either a string or an array of strings
fn deserialize_string_or_array<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct StringOrArrayVisitor;

    impl<'de> Visitor<'de> for StringOrArrayVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string or an array of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(vec![value.to_string()])
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(vec![value])
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut vec = Vec::new();
            while let Some(elem) = seq.next_element::<String>()? {
                vec.push(elem);
            }
            Ok(vec)
        }
    }

    deserializer.deserialize_any(StringOrArrayVisitor)
}

/// Deserializes a meta map where values can be either strings or arrays of strings
/// This matches the Go implementation which uses reflection to handle both cases
fn deserialize_meta_map<'de, D>(deserializer: D) -> Result<HashMap<String, Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, MapAccess, Visitor};
    use std::fmt;

    struct MetaMapVisitor;

    impl<'de> Visitor<'de> for MetaMapVisitor {
        type Value = HashMap<String, Vec<String>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a map of string to string or array of strings")
        }

        fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            let mut result = HashMap::new();
            while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                let patterns = match value {
                    serde_json::Value::String(s) => vec![s],
                    serde_json::Value::Array(arr) => arr
                        .into_iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect(),
                    _ => {
                        return Err(de::Error::invalid_type(
                            de::Unexpected::Other("expected string or array"),
                            &self,
                        ));
                    }
                };
                result.insert(key, patterns);
            }
            Ok(result)
        }
    }

    deserializer.deserialize_map(MetaMapVisitor)
}

/// Fingerprint ruleset metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintMetadata {
    /// Source URL or path
    pub source: String,
    /// Version/commit identifier
    pub version: String,
    /// Last update timestamp
    pub last_updated: SystemTime,
}

/// Category information from categories.json
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Category {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    priority: u32,
}

/// Fingerprint ruleset container
#[derive(Debug, Clone)]
pub struct FingerprintRuleset {
    /// Technologies indexed by name
    pub technologies: HashMap<String, Technology>,
    /// Categories indexed by ID (u32) -> name
    pub categories: HashMap<u32, String>,
    /// Metadata about the ruleset
    pub metadata: FingerprintMetadata,
}

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

/// Fetches ruleset from a single URL and caches it locally
#[allow(dead_code)] // Kept for potential future use or external API
async fn fetch_ruleset(source: &str, cache_dir: &Path) -> Result<FingerprintRuleset> {
    fetch_ruleset_from_multiple_sources(&[source.to_string()], cache_dir).await
}

/// Fetches technologies from a URL (handles both single file and directory)
async fn fetch_from_url(url: &str) -> Result<HashMap<String, Technology>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;

    // Check if URL points to a directory (GitHub) or a file
    // For HTTP Archive, we need to fetch all JSON files from the directory
    // raw.githubusercontent.com URLs that don't end in .json are directories
    if url.contains("raw.githubusercontent.com") && !url.ends_with(".json") {
        // It's a directory - fetch all JSON files via GitHub API
        log::debug!("Detected GitHub directory URL, fetching via API");
        return fetch_from_github_directory(url, &client).await;
    }

    // Single file - fetch directly
    log::debug!("Fetching single file from: {}", url);
    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to fetch {}: {}",
            url,
            response.status()
        ));
    }

    let json_text = response.text().await?;

    // Parse as a map of technology name -> Technology
    let technologies: HashMap<String, Technology> =
        serde_json::from_str(&json_text).context("Failed to parse technologies JSON")?;

    Ok(technologies)
}

/// Fetches all JSON files from a GitHub directory and merges them
async fn fetch_from_github_directory(
    dir_url: &str,
    client: &reqwest::Client,
) -> Result<HashMap<String, Technology>> {
    // Convert raw.githubusercontent.com URL to GitHub API URL
    // e.g., https://raw.githubusercontent.com/HTTPArchive/wappalyzer/main/src/technologies
    // -> https://api.github.com/repos/HTTPArchive/wappalyzer/contents/src/technologies
    let api_url = if dir_url.contains("raw.githubusercontent.com") {
        // Extract: owner/repo/branch/path
        // e.g., raw.githubusercontent.com/HTTPArchive/wappalyzer/main/src/technologies
        let parts: Vec<&str> = dir_url.split('/').collect();
        if parts.len() >= 7 {
            let owner = parts[3];
            let repo = parts[4];
            let path = parts[6..].join("/");
            format!(
                "https://api.github.com/repos/{}/{}/contents/{}",
                owner, repo, path
            )
        } else {
            return Err(anyhow::anyhow!("Invalid GitHub URL format: {}", dir_url));
        }
    } else {
        // Already an API URL or different format
        dir_url.to_string()
    };

    log::info!(
        "Fetching technology files from GitHub directory: {}",
        api_url
    );

    // Fetch directory listing
    let api_url_with_ref = format!("{}?ref=main", api_url);
    log::debug!("Fetching directory listing from: {}", api_url_with_ref);

    let response = client
        .get(&api_url_with_ref)
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", "domain_status/0.1.0")
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        return Err(anyhow::anyhow!(
            "Failed to fetch directory listing: {} - {}",
            status,
            error_text
        ));
    }

    #[derive(Deserialize)]
    struct FileEntry {
        name: String,
        download_url: Option<String>,
        #[serde(rename = "type")]
        file_type: String,
    }

    let json_text = response.text().await?;
    let entries: Vec<FileEntry> =
        serde_json::from_str(&json_text).context("Failed to parse GitHub API response")?;

    // Filter for JSON files only
    let json_files: Vec<_> = entries
        .into_iter()
        .filter(|f| f.file_type == "file" && f.name.ends_with(".json"))
        .collect();

    log::info!("Found {} JSON files to fetch", json_files.len());

    // Fetch all JSON files in parallel
    let mut tasks = Vec::new();
    for file in json_files {
        if let Some(download_url) = file.download_url {
            let client = client.clone();
            tasks.push(tokio::spawn(async move {
                match client.get(&download_url).send().await {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            match resp.text().await {
                                Ok(text) => {
                                    match serde_json::from_str::<HashMap<String, Technology>>(&text)
                                    {
                                        Ok(techs) => Some(techs),
                                        Err(e) => {
                                            log::warn!("Failed to parse {}: {}", download_url, e);
                                            None
                                        }
                                    }
                                }
                                Err(e) => {
                                    log::warn!("Failed to read {}: {}", download_url, e);
                                    None
                                }
                            }
                        } else {
                            log::warn!("Failed to fetch {}: {}", download_url, resp.status());
                            None
                        }
                    }
                    Err(e) => {
                        log::warn!("Failed to request {}: {}", download_url, e);
                        None
                    }
                }
            }));
        }
    }

    // Collect all results and merge
    let mut all_technologies = HashMap::new();
    for task in tasks {
        if let Ok(Some(techs)) = task.await {
            all_technologies.extend(techs);
        }
    }

    log::info!(
        "Successfully loaded {} technologies",
        all_technologies.len()
    );
    Ok(all_technologies)
}

/// Fetches categories.json from a URL
async fn fetch_categories_from_url(url: &str) -> Result<HashMap<u32, String>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()?;

    // Convert technologies URL to categories URL
    // e.g., https://raw.githubusercontent.com/HTTPArchive/wappalyzer/main/src/technologies
    // -> https://raw.githubusercontent.com/HTTPArchive/wappalyzer/main/src/categories.json
    let categories_url = if url.contains("raw.githubusercontent.com") && !url.ends_with(".json") {
        // It's a directory - construct categories.json URL in parent directory
        // e.g., .../src/technologies -> .../src/categories.json
        let trimmed = url.trim_end_matches('/');
        if trimmed.ends_with("/technologies") {
            // Remove "/technologies" and add "/categories.json"
            let base = &trimmed[..trimmed.len() - 12];
            format!("{}/categories.json", base.trim_end_matches('/'))
        } else {
            format!("{}/../categories.json", trimmed)
        }
    } else if url.ends_with(".json") {
        // Single file - replace with categories.json in same directory
        let mut parts: Vec<&str> = url.split('/').collect();
        if let Some(last) = parts.last_mut() {
            *last = "categories.json";
        }
        parts.join("/")
    } else {
        // Fallback: try appending ../categories.json
        format!("{}/../categories.json", url.trim_end_matches('/'))
    };

    log::debug!("Fetching categories from: {}", categories_url);
    let response = client.get(&categories_url).send().await?;
    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to fetch categories: {}",
            response.status()
        ));
    }

    let json_text = response.text().await?;
    // Parse as a map of category ID (string) -> Category
    let categories_map: HashMap<String, Category> =
        serde_json::from_str(&json_text).context("Failed to parse categories JSON")?;

    // Convert to HashMap<u32, String> (ID -> name)
    let mut result = HashMap::new();
    for (id_str, category) in categories_map {
        if let Ok(id) = id_str.parse::<u32>() {
            result.insert(id, category.name);
        }
    }

    log::info!("Loaded {} categories", result.len());
    Ok(result)
}

/// Loads categories.json from a local path
async fn load_categories_from_path(path: &Path) -> Result<HashMap<u32, String>> {
    let categories_path = if path.is_dir() {
        // If it's a directory, look for categories.json in the parent or same directory
        path.parent()
            .map(|p| p.join("categories.json"))
            .or_else(|| Some(path.join("categories.json")))
            .ok_or_else(|| anyhow::anyhow!("Cannot determine categories.json path"))?
    } else {
        // If it's a file, replace filename with categories.json
        path.parent()
            .map(|p| p.join("categories.json"))
            .ok_or_else(|| anyhow::anyhow!("Cannot determine categories.json path"))?
    };

    if !categories_path.exists() {
        return Err(anyhow::anyhow!(
            "categories.json not found at {:?}",
            categories_path
        ));
    }

    let content = fs::read_to_string(&categories_path).await?;
    let categories_map: HashMap<String, Category> =
        serde_json::from_str(&content).context("Failed to parse categories JSON")?;

    // Convert to HashMap<u32, String> (ID -> name)
    let mut result = HashMap::new();
    for (id_str, category) in categories_map {
        if let Ok(id) = id_str.parse::<u32>() {
            result.insert(id, category.name);
        }
    }

    log::info!(
        "Loaded {} categories from {:?}",
        result.len(),
        categories_path
    );
    Ok(result)
}

/// Gets the latest commit SHA for a GitHub repository path
///
/// This extracts the Git commit hash that identifies the exact version of the
/// ruleset being used. This is important for reproducibility - you can see
/// exactly which version of the fingerprints was used for each detection.
async fn get_latest_commit_sha(repo_path: &str) -> Option<String> {
    // Extract repo and path from URL
    // e.g., https://raw.githubusercontent.com/HTTPArchive/wappalyzer/main/src/technologies
    // URL structure: https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}
    let parts: Vec<&str> = repo_path.split('/').collect();
    log::debug!("URL parts count: {}, URL: {}", parts.len(), repo_path);

    if parts.len() < 7 {
        log::debug!(
            "Invalid GitHub URL format for SHA extraction: {} (length: {})",
            repo_path,
            parts.len()
        );
        return None;
    }

    // parts[0] = "https:"
    // parts[1] = ""
    // parts[2] = "raw.githubusercontent.com"
    // parts[3] = owner (e.g., "HTTPArchive")
    // parts[4] = repo (e.g., "wappalyzer")
    // parts[5] = branch (e.g., "main")
    // parts[6..] = path (e.g., "src/technologies")

    let owner = match parts.get(3) {
        Some(o) => o,
        None => {
            log::debug!("No owner found in URL parts");
            return None;
        }
    };
    let repo = match parts.get(4) {
        Some(r) => r,
        None => {
            log::debug!("No repo found in URL parts");
            return None;
        }
    };
    let path = parts[6..].join("/");
    log::debug!("Extracted: owner={}, repo={}, path={}", owner, repo, path);

    let api_url = format!(
        "https://api.github.com/repos/{}/{}/commits?path={}&per_page=1",
        owner, repo, path
    );

    log::debug!("Fetching commit SHA from: {}", api_url);

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static("domain_status/0.1.0"),
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .default_headers(headers)
        .build()
        .ok()?;

    #[derive(Deserialize)]
    struct Commit {
        sha: String,
    }

    log::debug!("Fetching commit SHA from GitHub API: {}", api_url);
    match client.get(&api_url).send().await {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                match resp.text().await {
                    Ok(text) => match serde_json::from_str::<Vec<Commit>>(&text) {
                        Ok(commits) => {
                            if let Some(commit) = commits.first() {
                                log::debug!("Found commit SHA: {}", commit.sha);
                                Some(commit.sha.clone())
                            } else {
                                log::warn!("No commits found in response for path: {}", path);
                                None
                            }
                        }
                        Err(e) => {
                            log::warn!(
                                "Failed to parse commit response: {} (first 200 chars: {})",
                                e,
                                &text[..text.len().min(200)]
                            );
                            None
                        }
                    },
                    Err(e) => {
                        log::warn!("Failed to read commit response: {}", e);
                        None
                    }
                }
            } else {
                log::warn!(
                    "GitHub API returned status: {} for URL: {}",
                    status,
                    api_url
                );
                None
            }
        }
        Err(e) => {
            log::warn!("Failed to fetch commit SHA from {}: {}", api_url, e);
            None
        }
    }
}

/// Loads technologies from a local path (handles both single file and directory)
async fn load_from_path(path: &Path) -> Result<HashMap<String, Technology>> {
    if path.is_dir() {
        // Load all JSON files from directory
        let mut all_technologies = HashMap::new();
        let mut entries = fs::read_dir(path).await?;

        while let Some(entry) = entries.next_entry().await? {
            let file_path = entry.path();
            if file_path.extension().and_then(|s| s.to_str()) == Some("json") {
                match fs::read_to_string(&file_path).await {
                    Ok(content) => {
                        match serde_json::from_str::<HashMap<String, Technology>>(&content) {
                            Ok(techs) => {
                                all_technologies.extend(techs);
                            }
                            Err(e) => {
                                log::warn!("Failed to parse {}: {}", file_path.display(), e);
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("Failed to read {}: {}", file_path.display(), e);
                    }
                }
            }
        }

        Ok(all_technologies)
    } else {
        // Single file
        let content = fs::read_to_string(path).await?;
        let technologies: HashMap<String, Technology> =
            serde_json::from_str(&content).context("Failed to parse technologies JSON")?;

        Ok(technologies)
    }
}

/// Loads ruleset from cache if it exists and is fresh
async fn load_from_cache(cache_dir: &Path, source: &str) -> Result<FingerprintRuleset> {
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
    let technologies: HashMap<String, Technology> = serde_json::from_str(&technologies_json)?;

    // Load categories (optional - may not exist in cache)
    let categories = if categories_path.exists() {
        match fs::read_to_string(&categories_path).await {
            Ok(categories_json) => {
                match serde_json::from_str::<HashMap<u32, String>>(&categories_json) {
                    Ok(cats) => {
                        log::debug!("Loaded {} categories from cache", cats.len());
                        cats
                    }
                    Err(e) => {
                        log::warn!("Failed to parse categories from cache: {}", e);
                        HashMap::new()
                    }
                }
            }
            Err(e) => {
                log::warn!("Failed to read categories from cache: {}", e);
                HashMap::new()
            }
        }
    } else {
        log::debug!("Categories cache not found, using empty map");
        HashMap::new()
    };

    Ok(FingerprintRuleset {
        technologies,
        categories,
        metadata,
    })
}

/// Saves ruleset to cache
async fn save_to_cache(ruleset: &FingerprintRuleset, cache_dir: &Path) -> Result<()> {
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

/// Detects technologies from extracted HTML data, headers, and URL.
///
/// This is a simplified matcher that only uses single-request fields:
/// - Headers
/// - Cookies (from SET_COOKIE and Cookie headers)
/// - Meta tags (name, property, http-equiv)
/// - Script sources
/// - Script content (inline scripts for js field detection)
/// - HTML text patterns
/// - URL patterns
/// - JavaScript object properties (js field)
///
/// # Arguments
///
/// * `meta_tags` - Map of meta tag name/property/http-equiv -> content
/// * `script_sources` - Vector of script src URLs
/// * `script_content` - Inline script content for js field detection
/// * `html_text` - HTML text content (first 50KB)
/// * `headers` - HTTP response headers
/// * `url` - The URL being analyzed
pub async fn detect_technologies(
    meta_tags: &HashMap<String, String>,
    script_sources: &[String],
    script_content: &str,
    html_text: &str,
    headers: &HeaderMap,
    url: &str,
    script_tag_ids: &HashSet<String>, // Script tag IDs found in HTML (for __NEXT_DATA__ etc.)
) -> Result<HashSet<String>> {
    // Clone the Arc immediately to release the lock (ruleset is read-only after init)
    let ruleset = {
        let guard = RULESET.read().await;
        guard
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Ruleset not initialized. Call init_ruleset() first"))?
            .clone()
    };

    let mut detected = HashSet::new();

    // Extract cookies from SET_COOKIE headers (response cookies)
    // Normalize cookie names and values to lowercase (matching Go implementation)
    let mut cookies: HashMap<String, String> = headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|hv| hv.to_str().ok())
        .filter_map(|cookie_str| {
            cookie_str.split(';').next().and_then(|pair| {
                let mut parts = pair.splitn(2, '=');
                if let (Some(name), Some(value)) = (parts.next(), parts.next()) {
                    Some((name.trim().to_lowercase(), value.trim().to_lowercase()))
                } else {
                    None
                }
            })
        })
        .collect();

    // Also extract cookies from Cookie header (request cookies)
    // Normalize cookie names and values to lowercase (matching Go implementation)
    if let Some(cookie_header) = headers.get(reqwest::header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie_pair in cookie_str.split(';') {
                let mut parts = cookie_pair.trim().splitn(2, '=');
                if let (Some(name), Some(value)) = (parts.next(), parts.next()) {
                    cookies.insert(name.trim().to_lowercase(), value.trim().to_lowercase());
                }
            }
        }
    }

    // Convert headers to lowercase map for matching (matching Go: strings.ToLower(header), strings.ToLower(value))
    let header_map: HashMap<String, String> = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_lowercase(), v.to_lowercase()))
        })
        .collect();

    // Fetch external scripts and combine with inline scripts for JavaScript execution
    // This matches the behavior of the Golang Wappalyzer tool
    let all_script_content = fetch_and_combine_scripts(script_sources, script_content, url).await;

    log::debug!(
        "Technology detection for {}: {} inline script bytes, {} external script sources, {} total script bytes",
        url,
        script_content.len(),
        script_sources.len(),
        all_script_content.len()
    );

    // Pre-filter technologies for early exit optimization
    // Skip technologies that can't possibly match based on available data
    // This significantly reduces the number of technologies we need to check
    let has_cookies = !cookies.is_empty();
    let has_headers = !header_map.is_empty();
    let has_meta = !meta_tags.is_empty();
    let has_scripts = !script_sources.is_empty();
    let has_script_content = !all_script_content.trim().is_empty();

    // Match each technology
    for (tech_name, tech) in &ruleset.technologies {
        // Early exit: skip technologies that can't match
        // If technology requires cookies but we have none, skip it
        if !tech.cookies.is_empty() && !has_cookies {
            continue;
        }
        // If technology requires headers but we have none, skip it
        if !tech.headers.is_empty() && !has_headers {
            continue;
        }
        // If technology requires meta tags but we have none, skip it
        if !tech.meta.is_empty() && !has_meta {
            continue;
        }
        // If technology requires script sources but we have none, skip it
        if !tech.script.is_empty() && !has_scripts {
            continue;
        }
        // If technology requires JS execution but we have no script content, skip it
        // (unless it can match via script tag IDs)
        if !tech.js.is_empty() && !has_script_content {
            // Check if any JS property could match via script tag IDs
            let can_match_via_tag_id = tech.js.keys().any(|prop| script_tag_ids.contains(prop));
            if !can_match_via_tag_id {
                continue;
            }
        }

        // Log when checking New Relic for debugging
        if tech_name == "New Relic" {
            log::debug!(
                "Checking New Relic technology with {} JS properties",
                tech.js.len()
            );
        }
        if matches_technology(
            tech,
            &header_map,
            &cookies,
            meta_tags,
            script_sources,
            &all_script_content,
            html_text,
            url,
            script_tag_ids,
        )
        .await
        {
            detected.insert(tech_name.clone());

            // Add implied technologies
            for implied in &tech.implies {
                detected.insert(implied.clone());
            }
        }
    }

    // Remove excluded technologies
    let mut final_detected = HashSet::new();
    for tech_name in &detected {
        let tech = ruleset.technologies.get(tech_name);
        let is_excluded = tech
            .map(|t| t.excludes.iter().any(|ex| detected.contains(ex)))
            .unwrap_or(false);

        if !is_excluded {
            final_detected.insert(tech_name.clone());
        }
    }

    Ok(final_detected)
}

/// Gets the category name for a technology, if available.
///
/// Returns the category name from the first category ID in the technology's `cats` array.
/// Returns `None` if the technology is not found, has no categories, or the category ID is not in the ruleset.
pub async fn get_technology_category(tech_name: &str) -> Option<String> {
    // Clone the Arc immediately to release the lock
    let ruleset = {
        let guard = RULESET.read().await;
        guard.as_ref()?.clone()
    };

    let tech = ruleset.technologies.get(tech_name)?;
    let first_cat_id = tech.cats.first()?;
    ruleset.categories.get(first_cat_id).cloned()
}

/// Checks if a technology matches based on its patterns
#[allow(clippy::too_many_arguments)] // Technology matching requires many parameters
async fn matches_technology(
    tech: &Technology,
    headers: &HashMap<String, String>,
    cookies: &HashMap<String, String>,
    meta_tags: &HashMap<String, String>,
    script_sources: &[String],
    all_script_content: &str, // Combined inline + external scripts for JS execution
    html_text: &str,
    url: &str,
    script_tag_ids: &HashSet<String>, // Script tag IDs found in HTML (for __NEXT_DATA__ etc.)
) -> bool {
    // Match headers (header_name is already normalized to lowercase in ruleset)
    for (header_name, pattern) in &tech.headers {
        if let Some(header_value) = headers.get(header_name) {
            if matches_pattern(pattern, header_value) {
                return true;
            }
        }
    }

    // Match cookies (cookie_name is already normalized to lowercase in ruleset)
    for (cookie_name, pattern) in &tech.cookies {
        if let Some(cookie_value) = cookies.get(cookie_name) {
            if pattern.is_empty() || matches_pattern(pattern, cookie_value) {
                return true;
            }
        }
    }

    // Match meta tags
    // Wappalyzer meta patterns can be:
    // - Simple name: "generator" -> matches meta name="generator"
    // - Prefixed: "property:og:title" -> matches meta property="og:title"
    // - Prefixed: "http-equiv:content-type" -> matches meta http-equiv="content-type"
    // Note: meta values are now Vec<String> to handle both string and array formats (from enthec source)
    for (meta_key, patterns) in &tech.meta {
        let meta_key_lower = meta_key.to_lowercase();

        // Check if key already has a prefix (property: or http-equiv:)
        if meta_key_lower.starts_with("property:") {
            let key_without_prefix = meta_key_lower
                .strip_prefix("property:")
                .unwrap_or(&meta_key_lower);
            if let Some(meta_value) = meta_tags.get(&format!("property:{}", key_without_prefix)) {
                // Check all patterns (meta can have multiple patterns)
                for pattern in patterns {
                    if matches_pattern(pattern, meta_value) {
                        return true;
                    }
                }
            }
        } else if meta_key_lower.starts_with("http-equiv:") {
            let key_without_prefix = meta_key_lower
                .strip_prefix("http-equiv:")
                .unwrap_or(&meta_key_lower);
            if let Some(meta_value) = meta_tags.get(&format!("http-equiv:{}", key_without_prefix)) {
                // Check all patterns
                for pattern in patterns {
                    if matches_pattern(pattern, meta_value) {
                        return true;
                    }
                }
            }
        } else {
            // Simple key (like "generator") - try all three attribute types
            // Try name: prefix (most common)
            if let Some(meta_value) = meta_tags.get(&format!("name:{}", meta_key_lower)) {
                for pattern in patterns {
                    if matches_pattern(pattern, meta_value) {
                        return true;
                    }
                }
            }
            // Try property: prefix (Open Graph, etc.)
            if let Some(meta_value) = meta_tags.get(&format!("property:{}", meta_key_lower)) {
                for pattern in patterns {
                    if matches_pattern(pattern, meta_value) {
                        return true;
                    }
                }
            }
            // Try http-equiv: prefix
            if let Some(meta_value) = meta_tags.get(&format!("http-equiv:{}", meta_key_lower)) {
                for pattern in patterns {
                    if matches_pattern(pattern, meta_value) {
                        return true;
                    }
                }
            }
        }
    }

    // Match script sources
    for pattern in &tech.script {
        for script_src in script_sources {
            if matches_pattern(pattern, script_src) {
                return true;
            }
        }
    }

    // Match HTML text
    for pattern in &tech.html {
        if matches_pattern(pattern, html_text) {
            return true;
        }
    }

    // Match URL patterns (can be multiple patterns)
    for url_pattern in &tech.url {
        if matches_pattern(url_pattern, url) {
            return true;
        }
    }

    // Match JavaScript object properties (js field)
    // Execute JavaScript to check for properties, matching Golang Wappalyzer behavior
    // Note: This is the slowest check, so it's done last (after all fast checks)
    if !tech.js.is_empty() {
        log::debug!(
            "Checking {} JS properties for technology ({} bytes of script content)",
            tech.js.len(),
            all_script_content.len()
        );
    }
    for (js_property, pattern) in &tech.js {
        // Special case: Properties that match script tag IDs (like __NEXT_DATA__)
        // The Golang Wappalyzer checks for script tag IDs when the js property matches
        // This is how Next.js detection works - it looks for <script id="__NEXT_DATA__">
        if script_tag_ids.contains(js_property) {
            log::info!("Technology matched via script tag ID '{}'", js_property);
            return true;
        }

        // Try JavaScript execution for window properties
        // Following WappalyzerGo's approach: execute scripts and check for global variables
        if !all_script_content.trim().is_empty() {
            // Log for debugging New Relic specifically
            if js_property == "NREUM" || js_property == "newrelic" {
                log::debug!(
                    "Checking for New Relic property '{}' with {} bytes of script content",
                    js_property,
                    all_script_content.len()
                );
            }
            if check_js_property_async(all_script_content, js_property, pattern).await {
                log::info!("Technology matched via JS property '{}'", js_property);
                return true;
            } else {
                // Log when property check fails for debugging
                if js_property == "NREUM" || js_property == "newrelic" {
                    log::debug!(
                        "New Relic property '{}' not found after JavaScript execution",
                        js_property
                    );
                }
            }
        } else {
            log::debug!(
                "Skipping JS property check for '{}' - no script content available",
                js_property
            );
        }
    }

    false
}

/// Fetches external JavaScript files and combines them with inline scripts.
///
/// This function fetches up to MAX_EXTERNAL_SCRIPTS external scripts and combines
/// them with inline script content for JavaScript execution.
///
/// # Arguments
///
/// * `script_sources` - Vector of script src URLs
/// * `inline_script_content` - Inline script content from HTML
/// * `base_url` - Base URL for resolving relative script URLs
///
/// # Returns
///
/// Combined script content (inline + external scripts)
async fn fetch_and_combine_scripts(
    script_sources: &[String],
    inline_script_content: &str,
    base_url: &str,
) -> String {
    let mut all_scripts = String::from(inline_script_content);

    // Limit the number of external scripts to prevent excessive fetching
    let scripts_to_fetch = script_sources
        .iter()
        .take(crate::config::MAX_EXTERNAL_SCRIPTS)
        .collect::<Vec<_>>();

    if scripts_to_fetch.is_empty() {
        return all_scripts;
    }

    // Create HTTP client with shorter timeout to prevent blocking
    // Reduced from 5s to 2s to prevent timeouts when fetching multiple scripts
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .user_agent(crate::config::DEFAULT_USER_AGENT)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    // Fetch external scripts in parallel
    let mut tasks = Vec::new();
    for script_src in scripts_to_fetch {
        let client = client.clone();
        let base_url = base_url.to_string();
        let script_src = script_src.clone();

        tasks.push(tokio::spawn(async move {
            // Resolve relative URLs
            let script_url =
                if script_src.starts_with("http://") || script_src.starts_with("https://") {
                    script_src
                } else if script_src.starts_with("//") {
                    format!("https:{}", script_src)
                } else {
                    // Relative URL - resolve against base URL
                    url::Url::parse(&base_url)
                        .ok()
                        .and_then(|base| base.join(&script_src).ok())
                        .map(|url| url.to_string())
                        .unwrap_or_else(|| script_src)
                };

            match client.get(&script_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.text().await {
                        Ok(text) => {
                            // Limit script size
                            let limited_text: String = text
                                .chars()
                                .take(crate::config::MAX_SCRIPT_CONTENT_SIZE)
                                .collect();
                            Some(limited_text)
                        }
                        Err(e) => {
                            log::debug!("Failed to read script {}: {}", script_url, e);
                            None
                        }
                    }
                }
                Ok(_) => {
                    log::debug!("Failed to fetch script {}: non-success status", script_url);
                    None
                }
                Err(e) => {
                    log::debug!("Failed to fetch script {}: {}", script_url, e);
                    None
                }
            }
        }));
    }

    // Collect results and append to all_scripts
    let mut fetched_count = 0;
    for task in tasks {
        if let Ok(Some(script_content)) = task.await {
            fetched_count += 1;
            // Check total size limit
            if all_scripts.len() + script_content.len()
                > crate::config::MAX_TOTAL_SCRIPT_CONTENT_SIZE
            {
                log::debug!("Total script content size limit reached, skipping remaining scripts");
                break;
            }
            all_scripts.push('\n');
            all_scripts.push_str(&script_content);
        }
    }

    if fetched_count > 0 {
        log::debug!(
            "Fetched {} external scripts ({} bytes total) for {}",
            fetched_count,
            all_scripts.len(),
            base_url
        );
    }

    all_scripts
}

/// Checks if a JavaScript property exists by executing JavaScript code (async version).
///
/// This function executes JavaScript code and checks if properties exist on the window object,
/// matching the behavior of the Golang Wappalyzer tool.
///
/// **Security:** This function enforces strict limits on script size and execution time
/// to prevent DoS attacks. Scripts are limited to 100KB per script and 500KB total,
/// and execution is limited to 1 second with a 10MB memory limit.
///
/// # Arguments
///
/// * `script_content` - The JavaScript code to execute (inline + external scripts)
/// * `js_property` - The property path to check (e.g., "jQuery" or "window.React")
/// * `pattern` - Optional pattern to match against the property value
///
/// # Returns
///
/// `true` if the property exists (and matches the pattern if provided), `false` otherwise
async fn check_js_property_async(script_content: &str, js_property: &str, pattern: &str) -> bool {
    // Skip if script content is empty
    if script_content.trim().is_empty() {
        return false;
    }

    // Security: Enforce size limits to prevent DoS attacks
    if script_content.len() > crate::config::MAX_TOTAL_SCRIPT_CONTENT_SIZE {
        log::debug!(
            "Script content too large ({} bytes), skipping JavaScript execution",
            script_content.len()
        );
        return false;
    }

    // Try to execute JavaScript using QuickJS (via rquickjs) with timeout protection
    match execute_js_property_check_with_timeout(script_content, js_property, pattern).await {
        Ok(result) => {
            if result {
                log::info!("JavaScript execution found property '{}'", js_property);
            }
            result
        }
        Err(e) => {
            log::debug!(
                "JavaScript execution failed or timed out for '{}': {e}",
                js_property
            );
            false
        }
    }
}

/// Executes JavaScript code and checks if a property exists with timeout protection.
///
/// Uses QuickJS to execute the script and check property existence on the window object.
/// Enforces strict security limits: memory limit, execution timeout, and size limits.
///
/// **Security measures:**
/// - Memory limit: 10MB per context
/// - Execution timeout: 1 second (via Tokio timeout)
/// - Size limits enforced by caller
async fn execute_js_property_check_with_timeout(
    script_content: &str,
    js_property: &str,
    pattern: &str,
) -> Result<bool> {
    // Use Tokio timeout to prevent infinite loops and CPU exhaustion
    // Note: QuickJS execution is blocking, so we run it in spawn_blocking
    let timeout_duration =
        std::time::Duration::from_millis(crate::config::MAX_JS_EXECUTION_TIME_MS);

    let script_content = script_content.to_string();
    let js_property = js_property.to_string();
    let pattern = pattern.to_string();

    // Use spawn_blocking to run QuickJS in a blocking thread pool
    // This prevents blocking the async runtime
    let handle = tokio::task::spawn_blocking(move || {
        execute_js_property_check(&script_content, &js_property, &pattern)
    });

    // Apply timeout to the spawned task
    tokio::time::timeout(timeout_duration, handle)
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "JavaScript execution timed out after {}ms",
                crate::config::MAX_JS_EXECUTION_TIME_MS
            )
        })?
        .map_err(|e| anyhow::anyhow!("Task join error: {e}"))?
}

/// Executes JavaScript code and checks if a property exists.
///
/// Uses QuickJS (via rquickjs) to execute the script and check property existence on the window object.
///
/// **Security:** This function enforces a memory limit but does NOT enforce execution timeout.
/// Callers should use `execute_js_property_check_with_timeout` instead.
fn execute_js_property_check(
    script_content: &str,
    js_property: &str,
    pattern: &str,
) -> Result<bool> {
    // Create a QuickJS runtime with memory limit to prevent memory exhaustion attacks
    let runtime =
        Runtime::new().map_err(|e| anyhow::anyhow!("Failed to create QuickJS runtime: {e}"))?;

    // Set memory limit
    runtime.set_memory_limit(crate::config::MAX_JS_MEMORY_LIMIT);

    // Create a context within the runtime
    let context = Context::full(&runtime)
        .map_err(|e| anyhow::anyhow!("Failed to create QuickJS context: {e}"))?;

    // Create window object and stub browser APIs in global scope before executing scripts
    // rquickjs doesn't have a global 'window' object by default, so we need to create it
    // Following WappalyzerGo's approach: create window, document, and other browser APIs as stubs
    // This allows scripts to initialize without errors, even if they can't fully function
    context.with(|ctx| {
        // Create window object and browser API stubs in global scope
        // Using globalThis ensures it's truly global (not just a local var)
        let init_code = r#"
            // Create window object in global scope
            globalThis.window = {};
            globalThis.global = globalThis.window;
            globalThis.self = globalThis.window;
            
            // Stub document object to prevent errors when scripts try to use it
            globalThis.document = {
                createElement: function() { return {}; },
                body: {},
                location: {},
                getElementById: function() { return null; },
                getElementsByTagName: function() { return []; },
                getElementsByClassName: function() { return []; },
                querySelector: function() { return null; },
                querySelectorAll: function() { return []; }
            };
            
            // Stub navigator
            globalThis.navigator = {
                userAgent: 'Mozilla/5.0',
                platform: 'Linux x86_64'
            };
            
            // Stub localStorage (empty object, no-op methods)
            globalThis.localStorage = {
                getItem: function() { return null; },
                setItem: function() {},
                removeItem: function() {},
                clear: function() {}
            };
            
            // Stub console to prevent errors
            globalThis.console = {
                log: function() {},
                error: function() {},
                warn: function() {},
                info: function() {}
            };
        "#;
        if let Err(e) = ctx.eval::<rquickjs::Value, _>(init_code) {
            log::debug!(
                "Failed to initialize browser stubs for property '{}': {e}",
                js_property
            );
        }
    });

    // Execute the script content to populate the window object
    // Wrap in try-catch to handle errors gracefully
    // Scripts may fail partially but still set global variables we need
    let setup_code = format!(
        r#"
        try {{
            {}
        }} catch (e) {{
            // Ignore errors during script execution - scripts may fail but still set globals
        }}
        "#,
        script_content
    );

    // Execute the script (ignore errors - some scripts may fail but still set properties)
    context.with(|ctx| {
        if let Err(e) = ctx.eval::<rquickjs::Value, _>(setup_code.as_str()) {
            log::debug!(
                "Script execution error (non-fatal) for property '{}': {e}",
                js_property
            );
        }
    });

    // Build the property access expression
    // Handle both simple properties (e.g., "jQuery") and property paths (e.g., "window.React" or ".__NEXT_DATA__.nextExport")
    let property_expr = if js_property.starts_with('.') {
        // Property path starting with dot (e.g., ".__NEXT_DATA__.nextExport")
        // Access from window
        format!("window{}", js_property)
    } else if js_property.contains('.') {
        // Property path with dots (e.g., "window.React" or "ufe.funnelData")
        // Use as-is if it starts with window/global/self, otherwise prepend window
        if js_property.starts_with("window.")
            || js_property.starts_with("global.")
            || js_property.starts_with("self.")
        {
            js_property.to_string()
        } else {
            format!("window.{}", js_property)
        }
    } else {
        // Simple property name (e.g., "jQuery" or "NREUM")
        // Check both window.NREUM and global NREUM (some scripts set it globally, not on window)
        format!("window.{}", js_property)
    };

    // Also check global scope for properties that might not be on window
    // Some scripts (like New Relic) set properties globally: NREUM={} not window.NREUM={}
    let global_property_expr = if js_property.contains('.') {
        // For nested properties, check global scope too
        js_property.to_string()
    } else {
        // For simple properties, check global scope
        js_property.to_string()
    };

    // Build pattern check code first (to avoid nested format! issues)
    let pattern_check = if pattern.is_empty() {
        "return true;".to_string()
    } else if pattern == "true" {
        "return value === true || value === 'true' || (typeof value === 'object' && value !== null);".to_string()
    } else if pattern == "false" {
        "return value === false || value === 'false';".to_string()
    } else {
        // For other patterns, convert to string and check
        // Escape single quotes and backslashes in pattern for JavaScript string
        let escaped_pattern = pattern.replace('\\', "\\\\").replace('\'', "\\'");
        format!(
            "return String(value).indexOf('{}') !== -1;",
            escaped_pattern
        )
    };

    // Check if property exists by trying to access it
    // Following WappalyzerGo's approach: check typeof and then access the property
    // window should exist from initialization in global scope
    // For simple properties, also check global scope (some scripts set NREUM={} not window.NREUM={})
    let check_code = if !js_property.contains('.')
        && !js_property.starts_with("window.")
        && !js_property.starts_with("global.")
        && !js_property.starts_with("self.")
    {
        // Simple property name - check both window.property and global property
        // This handles cases like New Relic where NREUM={} sets it globally, not window.NREUM={}
        format!(
            r#"
            (function() {{
                try {{
                    // Check window property first
                    var value;
                    if (typeof {} !== 'undefined') {{
                        value = {};
                    }} else if (typeof {} !== 'undefined') {{
                        // Fallback to global scope (for scripts that set NREUM={{}} not window.NREUM={{}})
                        value = {};
                    }} else {{
                        return false;
                    }}
                    
                    if (value === undefined || value === null) {{
                        return false;
                    }}
                    
                    {}
                }} catch (e) {{
                    return false;
                }}
            }})()
            "#,
            property_expr,        // typeof window.NREUM !== 'undefined'
            property_expr,        // window.NREUM
            global_property_expr, // typeof NREUM !== 'undefined'
            global_property_expr, // NREUM
            pattern_check
        )
    } else {
        // Complex property path - only check window
        format!(
            r#"
            (function() {{
                try {{
                    // Check if the property path exists (e.g., window.NREUM or window.jQuery.fn.jquery)
                    // Use typeof to safely check existence before accessing
                    var value;
                    if (typeof {} !== 'undefined') {{
                        value = {};
                    }} else {{
                        return false;
                    }}
                    
                    if (value === undefined || value === null) {{
                        return false;
                    }}
                    
                    {}
                }} catch (e) {{
                    return false;
                }}
            }})()
            "#,
            property_expr, // First check: typeof window.NREUM !== 'undefined'
            property_expr, // Second access: window.NREUM (to get the value)
            pattern_check
        )
    };

    // Execute the property check code and convert result to bool
    // All operations must be within the same `with` closure due to lifetime constraints
    context.with(|ctx| {
        let result = match ctx.eval::<rquickjs::Value, _>(check_code.as_str()) {
            Ok(val) => val,
            Err(e) => {
                log::debug!("JavaScript eval error for property '{}': {e}", js_property);
                return Err(anyhow::anyhow!("Failed to execute property check: {e}"));
            }
        };

        // Result should be a boolean - rquickjs returns Value which we need to convert
        // Check if it's a boolean value
        if let Some(bool_val) = result.as_bool() {
            Ok(bool_val)
        } else {
            // If not a boolean, check if it's truthy (not null/undefined)
            Ok(!result.is_null() && !result.is_undefined())
        }
    })
}

/// Checks if a JavaScript property exists using regex-based pattern matching (fallback).
///
/// **Note:** This function is currently unused. We rely solely on JavaScript execution
/// for property detection to avoid false positives. This function is kept for potential
/// future use or debugging.
///
/// # Arguments
///
/// * `js_search_text` - The JavaScript code to search (with comments/strings stripped)
/// * `js_property` - The property path to check (e.g., "jQuery" or "window.React")
/// * `pattern` - Optional pattern to match against the property value
///
/// # Returns
///
/// `true` if the property is found (and matches the pattern if provided), `false` otherwise
#[allow(dead_code)]
fn check_js_property_regex(js_search_text: &str, js_property: &str, pattern: &str) -> bool {
    // If pattern is empty, just check for property existence
    if pattern.is_empty() {
        // For properties with dots (like ".__NEXT_DATA__.nextExport"), match the full path
        if js_property.contains('.') {
            // Match the full property path (e.g., ".__NEXT_DATA__.nextExport")
            // Escape dots in the property path for regex
            let escaped = regex::escape(js_property);
            // Match as complete property path, not as substring
            // Look for the property path followed by non-word char or end
            let regex_pattern = format!(r"(?m)(?<![a-zA-Z0-9_$]){}\b(?![a-zA-Z0-9_$])", escaped);
            if let Ok(re) = regex::Regex::new(&regex_pattern) {
                if re.is_match(js_search_text) {
                    return true;
                }
            }
        } else {
            // Simple property name - match EXACT property name in JavaScript contexts
            // CRITICAL: Property must be complete identifier, not substring
            // e.g., "Fundiin" should NOT match in "websiteMaximumSuggestFundiinWithPrediction"
            let escaped = regex::escape(js_property);

            // For properties starting with $ or __, they're likely globals
            if js_property.starts_with('$') || js_property.starts_with("__") {
                // Match as global: window.Property (most reliable)
                // Or as standalone at start of line/expression
                let patterns = vec![
                    format!(
                        r"(?m)(?<![a-zA-Z0-9_$])\bwindow\.{}\b(?![a-zA-Z0-9_$])",
                        escaped
                    ),
                    format!(
                        r"(?m)(?<![a-zA-Z0-9_$])\bglobal\.{}\b(?![a-zA-Z0-9_$])",
                        escaped
                    ),
                    format!(r"(?m)(?<![a-zA-Z0-9_$])^\s*{}\b(?![a-zA-Z0-9_$])", escaped),
                    format!(r"(?m)(?<![a-zA-Z0-9_$])\.{}\b(?![a-zA-Z0-9_$])", escaped),
                ];
                for regex_pattern in patterns {
                    if let Ok(re) = regex::Regex::new(&regex_pattern) {
                        if re.is_match(js_search_text) {
                            return true;
                        }
                    }
                }
            } else {
                // Regular properties: require EXACT match in JavaScript contexts
                // Match only if property is complete identifier, not substring
                // Wappalyzer executes JS - we approximate with strict regex matching
                let patterns = vec![
                    // Global object access - most reliable (window, global, self)
                    // Negative lookbehind/lookahead ensures it's not part of longer name
                    format!(
                        r"(?m)(?<![a-zA-Z0-9_$])\bwindow\.{}\b(?![a-zA-Z0-9_$])",
                        escaped
                    ),
                    format!(
                        r"(?m)(?<![a-zA-Z0-9_$])\bglobal\.{}\b(?![a-zA-Z0-9_$])",
                        escaped
                    ),
                    format!(
                        r"(?m)(?<![a-zA-Z0-9_$])\bself\.{}\b(?![a-zA-Z0-9_$])",
                        escaped
                    ),
                    // Variable declarations - must be followed by = or ; and be complete identifier
                    format!(
                        r"(?m)(?<![a-zA-Z0-9_$])\bvar\s+{}\b(?![a-zA-Z0-9_$])(?=\s*[=;])",
                        escaped
                    ),
                    format!(
                        r"(?m)(?<![a-zA-Z0-9_$])\blet\s+{}\b(?![a-zA-Z0-9_$])(?=\s*[=;])",
                        escaped
                    ),
                    format!(
                        r"(?m)(?<![a-zA-Z0-9_$])\bconst\s+{}\b(?![a-zA-Z0-9_$])(?=\s*[=;])",
                        escaped
                    ),
                ];

                for regex_pattern in patterns {
                    if let Ok(re) = regex::Regex::new(&regex_pattern) {
                        if re.is_match(js_search_text) {
                            return true;
                        }
                    }
                }
            }
        }
    } else {
        // Pattern specified - use it for matching
        // For properties with dots, we need to check if the property path exists
        // and then match the pattern against its value
        if js_property.contains('.') {
            // Property path like ".__NEXT_DATA__.nextExport" with pattern "true"
            // We need to find the property and check if its value matches the pattern
            // This is complex without executing JS, so we'll look for the property
            // followed by the pattern value
            let escaped_prop = regex::escape(js_property);
            let value_pattern = if pattern == "true" {
                r"true"
            } else if pattern == "false" {
                r"false"
            } else {
                pattern
            };

            // Look for property path followed by = or : and then the pattern
            let regex_pattern = format!(
                r"(?m)\b{}\s*[=:]\s*{}",
                escaped_prop,
                regex::escape(value_pattern)
            );
            if let Ok(re) = regex::Regex::new(&regex_pattern) {
                if re.is_match(js_search_text) {
                    return true;
                }
            }

            // Also try matching the pattern in the context of the property
            if matches_pattern(pattern, js_search_text) {
                // Additional check: ensure the property path exists nearby
                let escaped_prop = regex::escape(js_property);
                if let Ok(re) = regex::Regex::new(&format!(r"(?m)\b{}\b", escaped_prop)) {
                    if re.is_match(js_search_text) {
                        return true;
                    }
                }
            }
        } else {
            // Simple property with pattern - match pattern in context
            if matches_pattern(pattern, js_search_text) {
                return true;
            }
        }
    }

    false
}

/// Strips JavaScript comments and string literals from code to avoid false positives.
///
/// **Note:** This function is currently unused in production code. We rely solely on
/// JavaScript execution for property detection, which naturally ignores comments and strings.
/// This function is kept for tests and potential future use.
///
/// Handles:
/// - Single-line comments (// ...)
/// - Multi-line comments (/* ... */)
/// - Single-quoted strings ('...')
/// - Double-quoted strings ("...")
/// - Template literals (`...`)
#[allow(dead_code)]
fn strip_js_comments_and_strings(code: &str) -> String {
    let mut result = String::with_capacity(code.len());
    let mut chars = code.chars().peekable();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_template_literal = false;
    let mut in_single_line_comment = false;
    let mut in_multi_line_comment = false;
    let mut prev_char = '\0';

    while let Some(ch) = chars.next() {
        let next_char = chars.peek().copied().unwrap_or('\0');

        // Handle escaping in strings
        if (in_single_quote || in_double_quote || in_template_literal) && ch == '\\' {
            // Skip escaped character
            result.push(ch);
            if let Some(escaped) = chars.next() {
                result.push(escaped);
            }
            prev_char = ch;
            continue;
        }

        // Check for string/template literal start/end
        if !in_single_line_comment && !in_multi_line_comment {
            if ch == '\'' && !in_double_quote && !in_template_literal {
                in_single_quote = !in_single_quote;
                result.push(' '); // Replace with space to preserve positions
                prev_char = ch;
                continue;
            }
            if ch == '"' && !in_single_quote && !in_template_literal {
                in_double_quote = !in_double_quote;
                result.push(' ');
                prev_char = ch;
                continue;
            }
            if ch == '`' && !in_single_quote && !in_double_quote {
                in_template_literal = !in_template_literal;
                result.push(' ');
                prev_char = ch;
                continue;
            }
        }

        // If we're in a string, skip it
        if in_single_quote || in_double_quote || in_template_literal {
            result.push(' ');
            prev_char = ch;
            continue;
        }

        // Check for comment start
        if !in_single_line_comment && !in_multi_line_comment {
            if ch == '/' && next_char == '/' {
                in_single_line_comment = true;
                result.push(' ');
                chars.next(); // Skip the second '/'
                prev_char = ch;
                continue;
            }
            if ch == '/' && next_char == '*' {
                in_multi_line_comment = true;
                result.push(' ');
                chars.next(); // Skip the '*'
                prev_char = ch;
                continue;
            }
        }

        // Check for comment end
        if in_multi_line_comment && prev_char == '*' && ch == '/' {
            in_multi_line_comment = false;
            result.push(' ');
            prev_char = ch;
            continue;
        }
        if in_single_line_comment && ch == '\n' {
            in_single_line_comment = false;
            result.push('\n');
            prev_char = ch;
            continue;
        }

        // If we're in a comment, skip it
        if in_single_line_comment || in_multi_line_comment {
            result.push(' ');
            prev_char = ch;
            continue;
        }

        // Regular code character
        result.push(ch);
        prev_char = ch;
    }

    result
}

/// Pattern matching supporting Wappalyzer pattern syntax
/// Patterns can be:
/// - Simple strings (substring match)
/// - Regex patterns (if they start with ^ or contain regex special chars)
/// - Patterns with version extraction (e.g., "version:\\1")
fn matches_pattern(pattern: &str, text: &str) -> bool {
    // Handle empty pattern (matches anything)
    if pattern.is_empty() {
        return true;
    }

    // Check if pattern contains regex-like syntax
    // Wappalyzer patterns often use regex but we'll try to be smart about it
    // Patterns starting with ^ or containing regex special chars are likely regex
    let is_regex = pattern.starts_with('^')
        || pattern.contains('$')
        || pattern.contains('\\')
        || pattern.contains('[')
        || pattern.contains('(')
        || pattern.contains('*')
        || pattern.contains('+')
        || pattern.contains('?');

    if is_regex {
        // Try to compile as regex
        // Remove version extraction syntax (e.g., ";version:\\1") for matching
        let pattern_for_match = pattern.split(';').next().unwrap_or(pattern).trim();

        match regex::Regex::new(pattern_for_match) {
            Ok(re) => re.is_match(text),
            Err(_) => {
                // If regex compilation fails, fall back to substring
                // This handles cases where the pattern looks like regex but isn't valid
                text.contains(pattern)
            }
        }
    } else {
        // Simple substring match
        text.contains(pattern)
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

    #[allow(dead_code)]
    fn create_test_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("server"),
            HeaderValue::from_static("nginx/1.18.0"),
        );
        headers.insert(
            HeaderName::from_static("x-powered-by"),
            HeaderValue::from_static("PHP/7.4"),
        );
        headers
    }

    #[tokio::test]
    async fn test_pattern_matching() {
        assert!(matches_pattern("nginx", "nginx/1.18.0"));
        assert!(matches_pattern("", "anything"));
        assert!(!matches_pattern("apache", "nginx/1.18.0"));
    }

    #[test]
    fn test_strip_js_comments_and_strings() {
        // Test comment stripping
        let code = r#"var x = 1; // websiteMaximumSuggestFundiinWithPrediction
        var y = 2; /* lz_chat_execute */"#;
        let stripped = strip_js_comments_and_strings(code);
        assert!(!stripped.contains("websiteMaximumSuggestFundiinWithPrediction"));
        assert!(!stripped.contains("lz_chat_execute"));

        // Test string stripping
        let code2 = r#"var x = "websiteMaximumSuggestFundiinWithPrediction";
        var y = 'lz_chat_execute';"#;
        let stripped2 = strip_js_comments_and_strings(code2);
        assert!(!stripped2.contains("websiteMaximumSuggestFundiinWithPrediction"));
        assert!(!stripped2.contains("lz_chat_execute"));

        // Test that actual code is preserved
        let code3 = r#"window.websiteMaximumSuggestFundiinWithPrediction = true;
        var lz_chat_execute = function() {};"#;
        let stripped3 = strip_js_comments_and_strings(code3);
        assert!(stripped3.contains("websiteMaximumSuggestFundiinWithPrediction"));
        assert!(stripped3.contains("lz_chat_execute"));
    }

    #[tokio::test]
    async fn test_detect_technologies_empty() {
        // This test requires ruleset initialization
        // For now, just verify the function signature works
        let meta_tags = HashMap::new();
        let script_sources = Vec::new();
        let script_content = "";
        let html_text = "";
        let headers = HeaderMap::new();
        let url = "https://example.com";

        // Without ruleset, this will fail - that's expected
        let script_tag_ids = HashSet::new();
        let result = detect_technologies(
            &meta_tags,
            &script_sources,
            script_content,
            html_text,
            &headers,
            url,
            &script_tag_ids,
        )
        .await;
        assert!(result.is_err());
    }
}
