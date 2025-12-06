//! WHOIS/RDAP domain lookup using whois-service crate

mod cache;
mod parse;
mod types;

use anyhow::Result;
use std::path::{Path, PathBuf};

use whois_service::WhoisClient;

pub use types::WhoisResult;

use cache::{load_from_cache, save_to_cache};
use parse::convert_parsed_data;

/// Default cache directory for WHOIS data
const DEFAULT_CACHE_DIR: &str = ".whois_cache";

/// Performs a WHOIS lookup for a domain
///
/// This function uses the `whois-service` crate which:
/// - Automatically tries RDAP first, then falls back to WHOIS
/// - Handles IANA bootstrap for TLD discovery
/// - Implements per-server rate limiting
/// - Provides structured parsing
///
/// # Arguments
///
/// * `domain` - The domain to look up (e.g., "example.com")
/// * `cache_dir` - Optional cache directory for storing WHOIS data
///
/// # Returns
///
/// Returns WHOIS information if available, or None if lookup fails
pub async fn lookup_whois(domain: &str, cache_dir: Option<&Path>) -> Result<Option<WhoisResult>> {
    let cache_path = cache_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CACHE_DIR));

    // Check cache first
    if let Some(cached) = load_from_cache(&cache_path, domain)? {
        log::debug!("WHOIS cache hit for {}", domain);
        return Ok(Some(cached.result.into()));
    }

    log::info!("Starting WHOIS lookup for domain: {}", domain);

    // Use whois-service client (create new instance each time since it's lightweight)
    let client = WhoisClient::new()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create WHOIS client: {}", e))?;
    match client.lookup(domain).await {
        Ok(response) => {
            log::debug!("WHOIS lookup successful for {}", domain);
            let result = convert_parsed_data(&response);

            // Cache the result
            save_to_cache(&cache_path, domain, &result)?;

            Ok(Some(result))
        }
        Err(e) => {
            log::warn!("WHOIS lookup failed for {}: {}", domain, e);
            Ok(None)
        }
    }
}
