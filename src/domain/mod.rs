//! Domain extraction and normalization utilities.
//!
//! This module provides functions to extract and normalize domain names from URLs
//! using the Public Suffix List (PSL) to correctly identify registrable domains.
//!
//! Key functions:
//! - `extract_domain()` - Extracts the registrable domain from a URL
//! - `normalize_domain()` - Normalizes domain names (lowercase, removes www)
//! - `root_domain()` - Registrable domain (eTLD+1) from a bare hostname/FQDN
//!
//! ## Strict hostname validation
//!
//! For URL-based input, PSL and `url` parsing are sufficient. If we add features that
//! accept raw hostnames or subdomains (e.g. config-driven allowlists or subdomain
//! enumeration), consider using a crate such as [`addr`](https://crates.io/crates/addr)
//! for strict hostname validation (invalid labels, leading/trailing dots, character
//! allowlists) alongside PSL.

use anyhow::{Context, Result};

/// Extracts the registrable domain from a URL using PSL.
///
/// # Arguments
///
/// * `url` - The URL to extract the domain from
///
/// # Returns
///
/// The registrable domain (e.g., "example.com" from "<https://www.example.com/path>").
/// For IP-literal hosts, returns the IP string (used as the UPSERT/domain key).
/// Production SSRF checks still block private/loopback IPs before fetch.
///
/// # Errors
///
/// Returns an error if the URL cannot be parsed, has no host, or PSL extraction fails
/// for a non-IP hostname.
///
/// Uses `psl` to correctly extract the registrable domain, handling
/// both simple TLDs (e.g., "example.com") and multi-part TLDs (e.g., "example.co.uk").
pub fn extract_domain(url: &str) -> Result<String> {
    // First validate that the URL can be parsed
    let parsed = url::Url::parse(url).with_context(|| format!("Failed to parse URL: {url}"))?;

    // Ensure URL has a host component
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL '{url}' has no host component"))?;

    // IP literals have no PSL registrable domain; use the IP as the domain key so
    // wiremock/httptest integration tests and legitimate IP URL scans can succeed.
    if host.parse::<std::net::Ipv4Addr>().is_ok()
        || host.parse::<std::net::Ipv6Addr>().is_ok()
        || parsed
            .host()
            .is_some_and(|h| matches!(h, url::Host::Ipv4(_) | url::Host::Ipv6(_)))
    {
        return Ok(host.to_string());
    }

    // Use psl::domain_str() to get the registrable domain as a string
    psl::domain_str(host)
        .ok_or_else(|| anyhow::anyhow!("Failed to extract domain from URL: {url}"))
        .map(std::string::ToString::to_string)
}

/// Normalizes a domain name: ASCII-lowercase and strip a leading `www.`.
///
/// Does not apply PSL rules — use [`extract_domain`] or [`root_domain`] for
/// registrable-domain extraction.
///
/// Kept as a shared helper even when no production call site needs it yet;
/// unit tests cover the documented contract.
#[allow(dead_code)]
pub fn normalize_domain(domain: &str) -> String {
    let lower = domain.trim().to_ascii_lowercase();
    lower
        .strip_prefix("www.")
        .unwrap_or(lower.as_str())
        .to_string()
}

/// Returns the PSL registrable domain (eTLD+1) for a given FQDN/hostname.
///
/// Uses `psl::domain_str()` which correctly implements the Public Suffix List
/// algorithm. For most domains this gives the expected organizational domain
/// (e.g., `www.facebook.com` -> `facebook.com`).
///
/// For wildcard PSL entries like `*.cloudfront.net`, the registrable domain
/// equals the full FQDN (e.g., `d123.cloudfront.net`) because each subdomain
/// under a wildcard suffix is independently registered.
///
/// Bare public suffixes (e.g. `googleapis.com`) have no registrable domain in
/// PSL terms; we fall back to the FQDN itself when `psl::suffix_str` recognizes
/// it, so callers still get a stable organizational key.
pub fn root_domain(fqdn: &str) -> Option<String> {
    psl::domain_str(fqdn)
        .map(std::string::ToString::to_string)
        .or_else(|| {
            if psl::suffix_str(fqdn).is_some() {
                Some(fqdn.to_string())
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
