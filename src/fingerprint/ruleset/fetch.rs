//! URL fetching operations for fingerprint rulesets.
//!
//! This module handles fetching technologies and categories from URLs,
//! including GitHub directory fetching.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::time::Duration;

use crate::fingerprint::models::Technology;

use super::github::fetch_from_github_directory;

/// Fetches technologies from a URL (handles both single file and directory)
pub(crate) async fn fetch_from_url(url: &str) -> Result<HashMap<String, Technology>> {
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
