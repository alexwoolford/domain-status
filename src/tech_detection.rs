//! Technology detection using community-maintained fingerprint rulesets.
//!
//! This module implements technology detection by fetching and applying
//! fingerprint rules from community sources like HTTP Archive or Enthec.
//! Rules are cached locally and can be updated periodically.

use anyhow::{Context, Result};
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime};
use tokio::fs;
use tokio::sync::RwLock;

/// Default URL for HTTP Archive's Wappalyzer fork (technologies directory)
/// The rules are split into multiple JSON files (a.json, b.json, etc.)
const DEFAULT_FINGERPRINTS_URL: &str =
    "https://raw.githubusercontent.com/HTTPArchive/wappalyzer/main/src/technologies";

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
    /// Meta tag patterns: meta_name -> pattern
    #[serde(default)]
    pub meta: HashMap<String, String>,
    /// Script source patterns (can be string or array) - Wappalyzer uses "scriptSrc"
    #[serde(default)]
    #[serde(alias = "scriptSrc")]
    #[serde(deserialize_with = "deserialize_string_or_array")]
    pub script: Vec<String>,
    /// HTML text patterns (can be string or array)
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_string_or_array")]
    pub html: Vec<String>,
    /// URL patterns
    #[serde(default)]
    pub url: String,
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

/// Fingerprint ruleset container
#[derive(Debug, Clone)]
pub struct FingerprintRuleset {
    /// Technologies indexed by name
    pub technologies: HashMap<String, Technology>,
    /// Metadata about the ruleset
    pub metadata: FingerprintMetadata,
}

/// Global ruleset cache (lazy-loaded)
static RULESET: LazyLock<Arc<RwLock<Option<Arc<FingerprintRuleset>>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(None)));

/// Initializes the fingerprint ruleset from URL or local path.
///
/// Rules are cached locally and refreshed if older than 24 hours.
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

    let source = fingerprints_source.unwrap_or(DEFAULT_FINGERPRINTS_URL);
    let cache_path = cache_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CACHE_DIR));

    // Try to load from cache first
    if let Ok(ruleset) = load_from_cache(&cache_path, source).await {
        log::info!("Loaded fingerprint ruleset from cache: {}", source);
        let ruleset_arc = Arc::new(ruleset);
        *RULESET.write().await = Some(ruleset_arc.clone());
        return Ok(ruleset_arc);
    }

    // Fetch from source
    log::info!("Fetching fingerprint ruleset from: {}", source);
    let ruleset = fetch_ruleset(source, &cache_path).await?;
    let ruleset_arc = Arc::new(ruleset);
    *RULESET.write().await = Some(ruleset_arc.clone());
    Ok(ruleset_arc)
}

/// Fetches ruleset from URL and caches it locally
async fn fetch_ruleset(source: &str, cache_dir: &Path) -> Result<FingerprintRuleset> {
    let technologies = if source.starts_with("http://") || source.starts_with("https://") {
        // Fetch from URL - handle both single file and directory
        fetch_from_url(source).await?
    } else {
        // Load from local path - handle both single file and directory
        load_from_path(Path::new(source)).await?
    };

    // Get version from latest commit if possible
    // Check for GitHub URLs (both raw.githubusercontent.com and api.github.com)
    let is_github = source.contains("github.com") || source.contains("raw.githubusercontent.com");
    let version = if is_github {
        match get_latest_commit_sha(source).await {
            Some(sha) => {
                log::info!("Extracted commit SHA for fingerprints: {}", sha);
                sha
            }
            None => {
                log::warn!("Failed to extract commit SHA for {}", source);
                "unknown".to_string()
            }
        }
    } else {
        "unknown".to_string()
    };

    let metadata = FingerprintMetadata {
        source: source.to_string(),
        version,
        last_updated: SystemTime::now(),
    };

    let ruleset = FingerprintRuleset {
        technologies,
        metadata,
    };

    // Cache it
    save_to_cache(&ruleset, cache_dir).await?;

    Ok(ruleset)
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

    // Check if cache exists
    if !metadata_path.exists() || !technologies_path.exists() {
        return Err(anyhow::anyhow!("Cache not found"));
    }

    // Load metadata
    let metadata_json = fs::read_to_string(&metadata_path).await?;
    let metadata: FingerprintMetadata = serde_json::from_str(&metadata_json)?;

    // Check if cache is for the same source
    if metadata.source != source {
        return Err(anyhow::anyhow!("Cache source mismatch"));
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

    Ok(FingerprintRuleset {
        technologies,
        metadata,
    })
}

/// Saves ruleset to cache
async fn save_to_cache(ruleset: &FingerprintRuleset, cache_dir: &Path) -> Result<()> {
    fs::create_dir_all(cache_dir).await?;

    let metadata_path = cache_dir.join("metadata.json");
    let technologies_path = cache_dir.join("technologies.json");

    // Save metadata
    let metadata_json = serde_json::to_string_pretty(&ruleset.metadata)?;
    fs::write(&metadata_path, metadata_json).await?;

    // Save technologies
    let technologies_json = serde_json::to_string_pretty(&ruleset.technologies)?;
    fs::write(&technologies_path, technologies_json).await?;

    Ok(())
}

/// Detects technologies from extracted HTML data, headers, and URL.
///
/// This is a simplified matcher that only uses single-request fields:
/// - Headers
/// - Cookies
/// - Meta tags
/// - Script sources
/// - HTML text patterns
/// - URL patterns
///
/// # Arguments
///
/// * `meta_tags` - Map of meta tag name -> content
/// * `script_sources` - Vector of script src URLs
/// * `html_text` - HTML text content (first 50KB)
/// * `headers` - HTTP response headers
/// * `url` - The URL being analyzed
pub async fn detect_technologies(
    meta_tags: &HashMap<String, String>,
    script_sources: &[String],
    html_text: &str,
    headers: &HeaderMap,
    url: &str,
) -> Result<HashSet<String>> {
    let ruleset = RULESET.read().await;
    let ruleset = ruleset
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Ruleset not initialized. Call init_ruleset() first"))?;

    let mut detected = HashSet::new();

    // Extract cookies from headers
    let cookies: HashMap<String, String> = headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|hv| hv.to_str().ok())
        .filter_map(|cookie_str| {
            cookie_str.split(';').next().and_then(|pair| {
                let mut parts = pair.splitn(2, '=');
                if let (Some(name), Some(value)) = (parts.next(), parts.next()) {
                    Some((name.trim().to_lowercase(), value.trim().to_string()))
                } else {
                    None
                }
            })
        })
        .collect();

    // Convert headers to lowercase map for matching
    let header_map: HashMap<String, String> = headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_lowercase(), v.to_string()))
        })
        .collect();

    // Match each technology
    for (tech_name, tech) in &ruleset.technologies {
        if matches_technology(
            tech,
            &header_map,
            &cookies,
            &meta_tags,
            &script_sources,
            &html_text,
            url,
        ) {
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

/// Checks if a technology matches based on its patterns
fn matches_technology(
    tech: &Technology,
    headers: &HashMap<String, String>,
    cookies: &HashMap<String, String>,
    meta_tags: &HashMap<String, String>,
    script_sources: &[String],
    html_text: &str,
    url: &str,
) -> bool {
    // Match headers
    for (header_name, pattern) in &tech.headers {
        if let Some(header_value) = headers.get(&header_name.to_lowercase()) {
            if matches_pattern(pattern, header_value) {
                return true;
            }
        }
    }

    // Match cookies
    for (cookie_name, pattern) in &tech.cookies {
        if let Some(cookie_value) = cookies.get(&cookie_name.to_lowercase()) {
            if pattern.is_empty() || matches_pattern(pattern, cookie_value) {
                return true;
            }
        }
    }

    // Match meta tags
    for (meta_name, pattern) in &tech.meta {
        if let Some(meta_value) = meta_tags.get(&meta_name.to_lowercase()) {
            if matches_pattern(pattern, meta_value) {
                return true;
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

    // Match URL
    if !tech.url.is_empty() && matches_pattern(&tech.url, url) {
        return true;
    }

    false
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
pub async fn get_ruleset_metadata() -> Option<FingerprintMetadata> {
    let ruleset = RULESET.read().await;
    ruleset.as_ref().map(|r| r.metadata.clone())
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

    #[tokio::test]
    async fn test_detect_technologies_empty() {
        // This test requires ruleset initialization
        // For now, just verify the function signature works
        let meta_tags = HashMap::new();
        let script_sources = Vec::new();
        let html_text = "";
        let headers = HeaderMap::new();
        let url = "https://example.com";

        // Without ruleset, this will fail - that's expected
        let result = detect_technologies(&meta_tags, &script_sources, html_text, &headers, url).await;
        assert!(result.is_err());
    }
}
