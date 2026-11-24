//! GitHub commit SHA fetching operations.

use serde::Deserialize;
use std::time::Duration;

/// Gets the latest commit SHA for a GitHub repository path
///
/// This extracts the Git commit hash that identifies the exact version of the
/// ruleset being used. This is important for reproducibility - you can see
/// exactly which version of the fingerprints was used for each detection.
#[allow(clippy::cognitive_complexity, clippy::too_many_lines)] // Parses GitHub API JSON with multiple fallback paths for commit SHA extraction
pub(crate) async fn get_latest_commit_sha(repo_path: &str) -> Option<String> {
    // Extract repo and path from URL
    // e.g., https://raw.githubusercontent.com/HTTPArchive/wappalyzer/main/src/technologies
    // URL structure: https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}
    let parts: Vec<&str> = repo_path.split('/').collect();
    log::debug!("URL parts count: {}, URL: {}", parts.len(), repo_path);

    if parts.len() < 7 {
        log::debug!(
            "Invalid GitHub URL format for SHA extraction. Expected: \
            'https://raw.githubusercontent.com/owner/repo/branch/path', got: '{}' (parsed {} parts)",
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

    let Some(owner) = parts.get(3) else {
        log::debug!("No owner found in URL parts");
        return None;
    };
    let Some(repo) = parts.get(4) else {
        log::debug!("No repo found in URL parts");
        return None;
    };
    let path = parts[6..].join("/");
    log::debug!("Extracted: owner={owner}, repo={repo}, path={path}");

    let api_url = format!(
        "{}/repos/{owner}/{repo}/commits?path={path}&per_page=1",
        commit_api_origin()
    );

    log::debug!("Fetching commit SHA from: {api_url}");

    let resp = fetch_commit_response(&api_url).await?;

    #[derive(Deserialize)]
    struct Commit {
        sha: String,
    }

    log::debug!("Fetching commit SHA from GitHub API: {api_url}");
    let status = resp.status();
    if !status.is_success() {
        log::warn!("GitHub API returned status: {status} for URL: {api_url}");
        return None;
    }
    let text = read_capped_text(resp).await?;
    match serde_json::from_str::<Vec<Commit>>(&text) {
        Ok(commits) => {
            if let Some(commit) = commits.first() {
                log::debug!("Found commit SHA: {}", commit.sha);
                Some(commit.sha.clone())
            } else {
                log::warn!("No commits found in response for path: {path}");
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
    }
}

fn commit_api_origin() -> String {
    #[cfg(test)]
    if let Ok(origin) = std::env::var("DOMAIN_STATUS_TEST_GITHUB_API") {
        return origin;
    }
    "https://api.github.com".to_string()
}

async fn fetch_commit_response(api_url: &str) -> Option<reqwest::Response> {
    #[cfg(test)]
    if std::env::var_os("DOMAIN_STATUS_TEST_GITHUB_API").is_some() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .ok()?;
        return client.get(api_url).send().await.ok();
    }

    if crate::security::validate_url_safe(api_url).is_err() {
        log::warn!("Refusing unsafe commit-SHA URL: {api_url}");
        return None;
    }
    let client = crate::initialization::build_download_client(Duration::from_secs(10)).ok()?;
    match super::github_api_get(&client, api_url).await {
        Ok(resp) => Some(resp),
        Err(err) => {
            log::warn!("Failed to fetch commit SHA from {api_url}: {err}");
            None
        }
    }
}

/// Reads a GitHub commit response, refusing bodies over 1 MiB.
async fn read_capped_text(response: reqwest::Response) -> Option<String> {
    const MAX_COMMIT_BODY: usize = 1024 * 1024;
    let url = response.url().to_string();
    match crate::fetch::stream::stream_bytes_with_limit(
        response,
        MAX_COMMIT_BODY,
        crate::fetch::stream::OnLimit::Error,
        &url,
    )
    .await
    {
        Ok(streamed) => match String::from_utf8(streamed.into_bytes()) {
            Ok(text) => Some(text),
            Err(err) => {
                log::warn!("Commit response is not UTF-8: {err}");
                None
            }
        },
        Err(err) => {
            log::warn!("Failed to read commit response: {err}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_latest_commit_sha_invalid_url() {
        // Test with invalid URL format
        let result = get_latest_commit_sha("not-a-github-url").await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_get_latest_commit_sha_short_url() {
        // Test with URL that doesn't have enough parts
        let result = get_latest_commit_sha("https://raw.githubusercontent.com/owner").await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_get_latest_commit_sha_nonexistent_repo() {
        // Test with non-existent repository
        let url = "https://raw.githubusercontent.com/nonexistent/repo/main/path";
        let result = get_latest_commit_sha(url).await;
        // Should return None for non-existent repos
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_get_latest_commit_sha_owner_extraction_failure() {
        // Test that missing owner in URL parts returns None gracefully
        // This is critical - prevents panics from index out of bounds
        // The code at line 35-40 handles missing owner
        // We test with a URL that has fewer than 7 parts, which should return None at line 18
        // But we also want to test the specific owner extraction failure path
        // A URL with exactly 7 parts but empty owner would be: https://raw.githubusercontent.com//repo/branch/path
        // However, split('/') on that would give parts[3] = "" (empty string), not None
        // So the code at line 35 would get Some(""), which is valid
        // To test the None case, we need a URL with fewer than 4 parts before the path
        let url = "https://raw.githubusercontent.com";
        let result = get_latest_commit_sha(url).await;
        // Should return None (parts.len() < 7)
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_get_latest_commit_sha_repo_extraction_failure() {
        // Test that missing repo in URL parts returns None gracefully
        // This is critical - prevents panics from index out of bounds
        // The code at line 42-47 handles missing repo
        let url = "https://raw.githubusercontent.com/owner";
        let result = get_latest_commit_sha(url).await;
        // Should return None (parts.len() < 7)
        assert_eq!(result, None);
    }

    async fn mocked_response(body: Vec<u8>) -> reqwest::Response {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/body"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&server)
            .await;
        reqwest::Client::new()
            .get(format!("{}/body", server.uri()))
            .send()
            .await
            .expect("response")
    }

    #[tokio::test]
    async fn test_read_capped_text_returns_the_body() {
        let body = "a".repeat(4096);
        let text = read_capped_text(mocked_response(body.clone().into_bytes()).await)
            .await
            .expect("body within 1 MiB");
        assert_eq!(text, body);
    }

    #[tokio::test]
    async fn test_read_capped_text_rejects_over_one_mibibyte() {
        let body = vec![b'a'; 1024 * 1024 + 1];
        assert!(read_capped_text(mocked_response(body).await)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn test_get_latest_commit_sha_returns_sha_from_api_json() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/HTTPArchive/wappalyzer/commits"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"[{"sha":"abc123def456"}]"#))
            .mount(&server)
            .await;
        std::env::set_var("DOMAIN_STATUS_TEST_GITHUB_API", server.uri());
        struct ClearApiOrigin;
        impl Drop for ClearApiOrigin {
            fn drop(&mut self) {
                std::env::remove_var("DOMAIN_STATUS_TEST_GITHUB_API");
            }
        }
        let _clear = ClearApiOrigin;
        let sha = get_latest_commit_sha(
            "https://raw.githubusercontent.com/HTTPArchive/wappalyzer/main/src/technologies",
        )
        .await;
        assert_eq!(sha.as_deref(), Some("abc123def456"));
    }
}
