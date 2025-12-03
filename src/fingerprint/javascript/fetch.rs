//! JavaScript script fetching operations.
//!
//! This module handles fetching external JavaScript files and combining them
//! with inline scripts for execution.

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
pub(crate) async fn fetch_and_combine_scripts(
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
