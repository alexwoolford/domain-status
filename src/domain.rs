use anyhow::Result;
use publicsuffix::{List, Psl};
use reqwest::Url;

/// Extracts the registrable domain from a URL using the Public Suffix List.
///
/// # Arguments
///
/// * `list` - The Public Suffix List instance
/// * `url` - The URL to extract the domain from
///
/// # Returns
///
/// The registrable domain (e.g., "example.com" from "https://www.example.com/path")
///
/// # Errors
///
/// Returns an error if the URL cannot be parsed or if domain extraction fails.
pub fn extract_domain(list: &List, url: &str) -> Result<String> {
    let parsed = Url::parse(url)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Failed to extract host from {url}"))?;
    let d = list
        .domain(host.as_bytes())
        .ok_or_else(|| anyhow::anyhow!("Failed to extract domain from {url}"))?;
    Ok(String::from_utf8_lossy(d.as_bytes()).to_string())
}
