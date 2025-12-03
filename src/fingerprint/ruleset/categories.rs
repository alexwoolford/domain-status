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
pub(crate) async fn load_categories_from_path(path: &Path) -> Result<HashMap<u32, String>> {
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
