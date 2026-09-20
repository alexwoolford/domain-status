//! GitHub-specific operations for fetching fingerprint rulesets.
//!
//! This module handles fetching from GitHub directories and getting commit SHAs.

mod commit;
mod directory;

pub(crate) use commit::get_latest_commit_sha;
pub(crate) use directory::fetch_from_github_directory;

use anyhow::Result;
use reqwest::Client;

/// GitHub API User-Agent (`domain-status/<crate version>`).
pub(crate) const GITHUB_API_USER_AGENT: &str = concat!("domain-status/", env!("CARGO_PKG_VERSION"));

fn github_token() -> Option<String> {
    std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty())
}

/// GET a GitHub API URL. A rejected `GITHUB_TOKEN` (401) retries unauthenticated
/// so a stale token cannot wipe both default fingerprint sources.
pub(crate) async fn github_api_get(client: &Client, url: &str) -> Result<reqwest::Response> {
    let token = github_token();
    let mut request = client
        .get(url)
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", GITHUB_API_USER_AGENT);
    if let Some(ref token) = token {
        request = request.header("Authorization", format!("Bearer {token}"));
        log::info!("Using GitHub token for authentication (rate limit: 5000 requests/hour)");
    }
    let response = request.send().await?;
    if response.status().as_u16() == 401 && token.is_some() {
        log::warn!("GITHUB_TOKEN was rejected (401). Retrying the GitHub API without the token.");
        let retry = client
            .get(url)
            .header("Accept", "application/vnd.github.v3+json")
            .header("User-Agent", GITHUB_API_USER_AGENT)
            .send()
            .await?;
        return Ok(retry);
    }
    Ok(response)
}
