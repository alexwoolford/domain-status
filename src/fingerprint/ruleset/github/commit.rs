//! GitHub commit SHA fetching operations.

use reqwest;
use serde::Deserialize;
use std::time::Duration;

/// Gets the latest commit SHA for a GitHub repository path
///
/// This extracts the Git commit hash that identifies the exact version of the
/// ruleset being used. This is important for reproducibility - you can see
/// exactly which version of the fingerprints was used for each detection.
pub(crate) async fn get_latest_commit_sha(repo_path: &str) -> Option<String> {
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
