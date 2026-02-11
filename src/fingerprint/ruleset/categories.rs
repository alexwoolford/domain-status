//! Category loading operations for fingerprint rulesets.
//!
//! This module handles fetching and loading categories from URLs and local paths.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use tokio::fs;

use crate::fingerprint::models::Category;

/// Fetches categories.json from a URL
pub(crate) async fn fetch_categories_from_url(url: &str) -> Result<HashMap<u32, String>> {
    use crate::config::TCP_CONNECT_TIMEOUT_SECS;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .connect_timeout(Duration::from_secs(TCP_CONNECT_TIMEOUT_SECS)) // FIX: Enforce TCP connect timeout
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

#[cfg(test)]
mod tests {
    use super::*;
    use httptest::{matchers::*, responders::*, Expectation, Server};
    use tempfile::TempDir;
    use tokio::io::AsyncWriteExt;

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
        let result = fetch_categories_from_url(&url).await;
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
        let result = fetch_categories_from_url(&url).await;
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
        let result = fetch_categories_from_url(&url).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_fetch_categories_from_url_http_error() {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/categories.json"))
                .respond_with(status_code(404)),
        );

        let base_url = server.url("/");
        let url = format!("{}categories.json", base_url);
        let result = fetch_categories_from_url(&url).await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Failed to fetch categories") || error_msg.contains("404"));
    }

    #[tokio::test]
    async fn test_fetch_categories_from_url_invalid_json() {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/categories.json"))
                .respond_with(status_code(200).body("{ invalid json }")),
        );

        let base_url = server.url("/");
        let url = format!("{}categories.json", base_url);
        let result = fetch_categories_from_url(&url).await;
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("parse") || error_msg.contains("JSON"));
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
        let result = fetch_categories_from_url(&url).await;
        assert!(result.is_ok());
        let categories = result.unwrap();
        // Non-numeric ID should be skipped
        assert_eq!(categories.len(), 1);
        assert_eq!(categories.get(&1), Some(&"E-commerce".to_string()));
        assert!(!categories.contains_key(&0)); // "invalid" should not be parsed
    }

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
        let result = fetch_categories_from_url(&url).await;
        // Missing name field should cause deserialization error
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("missing field")
                || error_msg.contains("parse")
                || error_msg.contains("JSON")
        );
    }

    #[tokio::test]
    async fn test_fetch_categories_from_url_empty_categories() {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/categories.json"))
                .respond_with(status_code(200).body("{}")),
        );

        let base_url = server.url("/");
        let url = format!("{}categories.json", base_url);
        let result = fetch_categories_from_url(&url).await;
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
        assert!(error_msg.contains("parse") || error_msg.contains("JSON"));
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

    #[tokio::test]
    async fn test_load_categories_from_path_no_parent() {
        // Test with root path (no parent)
        let root_path = std::path::Path::new("/");
        let result = load_categories_from_path(root_path).await;
        // Should either find categories.json or fail gracefully
        // The exact behavior depends on whether /categories.json exists
        // We just verify it doesn't panic
        let _ = result;
    }
}
