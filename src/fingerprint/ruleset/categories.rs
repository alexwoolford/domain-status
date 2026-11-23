//! Category loading operations for fingerprint rulesets.
//!
//! This module handles fetching and loading categories from URLs and local paths.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use tokio::fs;

use crate::config::MAX_RULESET_DOWNLOAD_SIZE;
use crate::fetch::stream::{reject_if_content_length_exceeds, stream_bytes_with_limit, OnLimit};
use crate::fingerprint::models::Category;
use crate::security::validate_url_safe;

/// Fetches categories.json from a URL using the SSRF-safe download client.
pub(crate) async fn fetch_categories_from_url(url: &str) -> Result<HashMap<u32, String>> {
    let categories_url = categories_url_for_source(url);
    validate_url_safe(&categories_url)
        .with_context(|| format!("Unsafe categories URL rejected: {categories_url}"))?;
    let client = crate::initialization::build_download_client(Duration::from_secs(60))?;
    fetch_categories_with_client(&client, &categories_url).await
}

/// Maps a technologies source URL to the sibling `categories.json` URL.
fn categories_url_for_source(url: &str) -> String {
    // e.g., https://raw.githubusercontent.com/HTTPArchive/wappalyzer/main/src/technologies
    // -> https://raw.githubusercontent.com/HTTPArchive/wappalyzer/main/src/categories.json
    if url.contains("raw.githubusercontent.com")
        && !std::path::Path::new(url)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
    {
        // It's a directory - construct categories.json URL in parent directory
        // e.g., .../src/technologies -> .../src/categories.json
        let trimmed = url.trim_end_matches('/');
        if trimmed.ends_with("/technologies") {
            // Remove "/technologies" and add "/categories.json"
            let base = &trimmed[..trimmed.len() - 12];
            format!("{}/categories.json", base.trim_end_matches('/'))
        } else {
            format!("{trimmed}/../categories.json")
        }
    } else if std::path::Path::new(url)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
    {
        // Single file - replace with categories.json in same directory
        let mut parts: Vec<&str> = url.split('/').collect();
        if let Some(last) = parts.last_mut() {
            *last = "categories.json";
        }
        parts.join("/")
    } else {
        // Fallback: try appending ../categories.json
        format!("{}/../categories.json", url.trim_end_matches('/'))
    }
}

async fn fetch_categories_with_client(
    client: &reqwest::Client,
    categories_url: &str,
) -> Result<HashMap<u32, String>> {
    log::debug!("Fetching categories from: {categories_url}");
    let response = client.get(categories_url).send().await?;
    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to fetch categories: {}",
            response.status()
        ));
    }

    reject_if_content_length_exceeds(&response, MAX_RULESET_DOWNLOAD_SIZE, "Categories file")?;
    let streamed = stream_bytes_with_limit(
        response,
        MAX_RULESET_DOWNLOAD_SIZE,
        OnLimit::Error,
        categories_url,
    )
    .await
    .map_err(|err| anyhow::anyhow!("Categories file too large or unreadable: {err}"))?;
    let json_text = String::from_utf8(streamed.into_bytes())
        .context("Categories file contains invalid UTF-8")?;
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
pub(crate) async fn load_categories_from_path(path: &Path) -> Result<HashMap<u32, String>> {
    let categories_path = if path.is_dir() {
        // If it's a directory, look for categories.json in the parent or same directory
        path.parent()
            .map(|p| p.join("categories.json"))
            .or_else(|| Some(path.join("categories.json")))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot determine categories.json path. Checked: parent directory of '{}' and \
                    same directory. Ensure categories.json exists in the expected location.",
                    path.display()
                )
            })?
    } else {
        // If it's a file, replace filename with categories.json
        path.parent()
            .map(|p| p.join("categories.json"))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot determine categories.json path. Checked: parent directory of '{}'. \
                    Ensure categories.json exists in the expected location.",
                    path.display()
                )
            })?
    };

    if !categories_path.exists() {
        return Err(anyhow::anyhow!(
            "categories.json not found at {}",
            categories_path.display()
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
        "Loaded {} categories from {}",
        result.len(),
        categories_path.display()
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use httptest::{matchers::*, responders::*, Expectation, Server};
    use tempfile::TempDir;
    use tokio::io::AsyncWriteExt;

    /// Local JSON fixtures bind to loopback, which the SSRF client rejects.
    /// Parsing tests call the body reader directly; SSRF is covered separately.
    async fn fetch_categories_for_test(url: &str) -> Result<HashMap<u32, String>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()?;
        fetch_categories_with_client(&client, &categories_url_for_source(url)).await
    }

    #[tokio::test]
    async fn test_fetch_categories_from_url_rejects_loopback() {
        let err = fetch_categories_from_url("http://127.0.0.1/categories.json")
            .await
            .expect_err("loopback categories URL must be rejected");
        assert!(
            err.to_string().contains("Unsafe categories URL rejected"),
            "got: {err}"
        );
    }

    #[tokio::test]
    async fn test_fetch_categories_from_url_success() {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/categories.json")).respond_with(
                status_code(200).body(r#"{"1": {"name": "CMS"}, "2": {"name": "E-commerce"}}"#),
            ),
        );

        let base_url = server.url("/");
        let url = format!("{}categories.json", base_url);
        let result = fetch_categories_for_test(&url).await;
        assert!(result.is_ok());
        let categories = result.unwrap();
        assert_eq!(categories.len(), 2);
        assert_eq!(categories.get(&1), Some(&"CMS".to_string()));
        assert_eq!(categories.get(&2), Some(&"E-commerce".to_string()));
    }

    #[tokio::test]
    async fn test_fetch_categories_from_url_github_directory() {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/src/categories.json"))
                .respond_with(status_code(200).body(r#"{"1": {"name": "CMS"}}"#)),
        );

        let base_url = server.url("/");
        let url = format!("{}src/technologies", base_url);
        let result = fetch_categories_for_test(&url).await;
        assert!(result.is_ok());
        let categories = result.unwrap();
        assert_eq!(categories.get(&1), Some(&"CMS".to_string()));
    }

    #[tokio::test]
    async fn test_fetch_categories_from_url_single_json_file() {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/src/categories.json"))
                .respond_with(status_code(200).body(r#"{"1": {"name": "CMS"}}"#)),
        );

        let base_url = server.url("/");
        let url = format!("{}src/technologies.json", base_url);
        let result = fetch_categories_for_test(&url).await;
        assert!(result.is_ok());
    }

    /// Kills: `fetch_categories_from_url` returning `Err` without
    /// `"Failed to fetch categories"` (e.g. a bare status-only message).
    #[tokio::test]
    async fn test_fetch_categories_from_url_http_error() {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/categories.json"))
                .respond_with(status_code(404)),
        );

        let base_url = server.url("/");
        let url = format!("{}categories.json", base_url);
        let result = fetch_categories_for_test(&url).await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Failed to fetch categories"),
            "expected fetch-failed context, got: {error_msg}"
        );
    }

    /// Kills: `fetch_categories_from_url` dropping the
    /// `"Failed to parse categories JSON"` context on invalid JSON.
    #[tokio::test]
    async fn test_fetch_categories_from_url_invalid_json() {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/categories.json"))
                .respond_with(status_code(200).body("{ invalid json }")),
        );

        let base_url = server.url("/");
        let url = format!("{}categories.json", base_url);
        let result = fetch_categories_for_test(&url).await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Failed to parse categories JSON"),
            "expected parse-context, got: {error_msg}"
        );
    }

    #[tokio::test]
    async fn test_fetch_categories_from_url_non_numeric_id() {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/categories.json")).respond_with(
                status_code(200)
                    .body(r#"{"invalid": {"name": "CMS"}, "1": {"name": "E-commerce"}}"#),
            ),
        );

        let base_url = server.url("/");
        let url = format!("{}categories.json", base_url);
        let result = fetch_categories_for_test(&url).await;
        assert!(result.is_ok());
        let categories = result.unwrap();
        // Non-numeric ID should be skipped
        assert_eq!(categories.len(), 1);
        assert_eq!(categories.get(&1), Some(&"E-commerce".to_string()));
        assert!(!categories.contains_key(&0)); // "invalid" should not be parsed
    }

    /// Kills: `fetch_categories_from_url` flattening a missing `name` field so
    /// the source chain no longer contains serde's `missing field`.
    #[tokio::test]
    async fn test_fetch_categories_from_url_missing_name() {
        let server = Server::run();
        // Category struct requires name field, so missing name will cause deserialization error
        server.expect(
            Expectation::matching(request::method_path("GET", "/categories.json"))
                .respond_with(status_code(200).body(r#"{"1": {}}"#)),
        );

        let base_url = server.url("/");
        let url = format!("{}categories.json", base_url);
        let result = fetch_categories_for_test(&url).await;
        let err = result.expect_err("missing name must fail deserialize");
        assert!(
            err.to_string().contains("Failed to parse categories JSON"),
            "expected parse-context, got: {err}"
        );
        assert!(
            err.chain().any(|e| e.to_string().contains("missing field")),
            "source chain must name the missing field, got: {err:#}"
        );
    }

    /// Contract: `{}` loads as an empty map (`is_ok` then `len() == 0`).
    #[tokio::test]
    async fn test_fetch_categories_from_url_empty_categories() {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/categories.json"))
                .respond_with(status_code(200).body("{}")),
        );

        let base_url = server.url("/");
        let url = format!("{}categories.json", base_url);
        let result = fetch_categories_for_test(&url).await;
        assert!(result.is_ok());
        let categories = result.unwrap();
        assert_eq!(categories.len(), 0);
    }

    #[tokio::test]
    async fn test_load_categories_from_path_success() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let categories_path = temp_dir.path().join("categories.json");
        let mut file = tokio::fs::File::create(&categories_path)
            .await
            .expect("Failed to create test file");
        file.write_all(r#"{"1": {"name": "CMS"}, "2": {"name": "E-commerce"}}"#.as_bytes())
            .await
            .expect("Failed to write categories JSON");
        file.flush().await.expect("Failed to flush file");
        drop(file);

        let tech_path = temp_dir.path().join("technologies");
        let result = load_categories_from_path(&tech_path).await;
        assert!(result.is_ok());
        let categories = result.unwrap();
        assert_eq!(categories.len(), 2);
        assert_eq!(categories.get(&1), Some(&"CMS".to_string()));
    }

    #[tokio::test]
    async fn test_load_categories_from_path_file_not_found() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let tech_path = temp_dir.path().join("nonexistent");
        let result = load_categories_from_path(&tech_path).await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("not found") || error_msg.contains("No such file"),
            "Expected file not found error, got: {}",
            error_msg
        );
    }

    /// Kills: `load_categories_from_path` dropping the
    /// `"Failed to parse categories JSON"` context on invalid JSON.
    #[tokio::test]
    async fn test_load_categories_from_path_invalid_json() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let categories_path = temp_dir.path().join("categories.json");
        let mut file = tokio::fs::File::create(&categories_path)
            .await
            .expect("Failed to create test file");
        file.write_all(b"{ invalid json }")
            .await
            .expect("Failed to write invalid JSON");
        file.flush().await.expect("Failed to flush file");
        drop(file);

        let tech_path = temp_dir.path().join("technologies");
        let result = load_categories_from_path(&tech_path).await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Failed to parse categories JSON"),
            "expected parse-context, got: {error_msg}"
        );
    }

    #[tokio::test]
    async fn test_load_categories_from_path_directory() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let categories_path = temp_dir.path().join("categories.json");
        let mut file = tokio::fs::File::create(&categories_path)
            .await
            .expect("Failed to create test file");
        file.write_all(r#"{"1": {"name": "CMS"}}"#.as_bytes())
            .await
            .expect("Failed to write categories JSON");
        file.flush().await.expect("Failed to flush file");
        drop(file);

        // Test with directory path
        let tech_dir = temp_dir.path().join("technologies");
        tokio::fs::create_dir_all(&tech_dir)
            .await
            .expect("Failed to create technologies directory");
        let result = load_categories_from_path(&tech_dir).await;
        assert!(result.is_ok());
        let categories = result.unwrap();
        assert_eq!(categories.get(&1), Some(&"CMS".to_string()));
    }

    #[tokio::test]
    async fn test_load_categories_from_path_file_path() {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        // Create technologies directory
        let tech_dir = temp_dir.path().join("technologies");
        tokio::fs::create_dir_all(&tech_dir)
            .await
            .expect("Failed to create technologies directory");

        // Put categories.json in the technologies directory (parent of tech.json)
        // The function looks in the parent directory of the file
        let categories_path = tech_dir.join("categories.json");
        let mut file = tokio::fs::File::create(&categories_path)
            .await
            .expect("Failed to create test file");
        file.write_all(r#"{"1": {"name": "CMS"}}"#.as_bytes())
            .await
            .expect("Failed to write categories JSON");
        file.flush().await.expect("Failed to flush file");
        drop(file);

        // Test with file path in technologies subdirectory
        // The function should look in parent (tech_dir) for categories.json
        let tech_file = tech_dir.join("tech.json");
        tokio::fs::File::create(&tech_file)
            .await
            .expect("Failed to create tech.json");

        let result = load_categories_from_path(&tech_file).await;
        assert!(result.is_ok());
        let categories = result.unwrap();
        assert_eq!(categories.get(&1), Some(&"CMS".to_string()));
    }
}
