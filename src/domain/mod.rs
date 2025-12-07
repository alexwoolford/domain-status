//! Domain extraction and normalization utilities.
//!
//! This module provides functions to extract and normalize domain names from URLs
//! using the Public Suffix List (PSL) to correctly identify registrable domains.
//!
//! Key functions:
//! - `extract_domain()` - Extracts the registrable domain from a URL
//! - `normalize_domain()` - Normalizes domain names (lowercase, removes www)

use anyhow::{Context, Result};

/// Extracts the registrable domain from a URL using psl.
///
/// # Arguments
///
/// * `_list` - The psl::List instance (unused, kept for API compatibility)
/// * `url` - The URL to extract the domain from
///
/// # Returns
///
/// The registrable domain (e.g., "example.com" from "https://www.example.com/path")
///
/// # Errors
///
/// Returns an error if the URL cannot be parsed, if the URL is an IP address,
/// or if domain extraction fails.
///
/// Uses `psl` to correctly extract the registrable domain, handling
/// both simple TLDs (e.g., "example.com") and multi-part TLDs (e.g., "example.co.uk").
pub fn extract_domain(_list: &psl::List, url: &str) -> Result<String> {
    // First validate that the URL can be parsed
    let parsed = url::Url::parse(url).with_context(|| format!("Failed to parse URL: {}", url))?;

    // Ensure URL has a host component
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL '{}' has no host component", url))?;

    // Reject IP addresses (they don't have registrable domains)
    // Check both IPv4 and IPv6 addresses
    if host.parse::<std::net::Ipv4Addr>().is_ok()
        || host.parse::<std::net::Ipv6Addr>().is_ok()
        || parsed
            .host()
            .map(|h| matches!(h, url::Host::Ipv4(_) | url::Host::Ipv6(_)))
            .unwrap_or(false)
    {
        return Err(anyhow::anyhow!(
            "IP addresses do not have registrable domains: {}",
            host
        ));
    }

    // Use psl::domain_str() to get the registrable domain as a string
    psl::domain_str(host)
        .ok_or_else(|| anyhow::anyhow!("Failed to extract domain from URL: {}", url))
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
