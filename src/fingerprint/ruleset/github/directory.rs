//! GitHub directory fetching operations.

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;

use crate::fingerprint::models::Technology;

/// Fetches all JSON files from a GitHub directory and merges them
pub(crate) async fn fetch_from_github_directory(
    dir_url: &str,
    client: &Client,
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

