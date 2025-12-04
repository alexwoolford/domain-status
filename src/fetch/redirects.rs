//! HTTP redirect chain resolution.
//!
//! This module handles following redirect chains manually to track the full path
//! from initial URL to final destination.

use anyhow::{Error, Result};
use reqwest::Url;

use crate::fetch::request::RequestHeaders;

/// Resolves the redirect chain for a URL, following redirects up to a maximum number of hops.
///
/// # Arguments
///
/// * `start_url` - The initial URL to start from
/// * `max_hops` - Maximum number of redirect hops to follow (must be > 0)
/// * `client` - HTTP client with redirects disabled (for manual tracking)
///
/// # Returns
///
/// A tuple of (final_url, redirect_chain) where:
/// - `final_url` is the final URL after all redirects
/// - `redirect_chain` is a vector of all URLs in the chain (including final URL)
///
/// # Errors
///
/// Returns an error if HTTP requests fail, URL parsing fails, or max_hops is 0.
pub async fn resolve_redirect_chain(
    start_url: &str,
    max_hops: usize,
    client: &reqwest::Client,
) -> Result<(String, Vec<String>), Error> {
    // Validate max_hops
    if max_hops == 0 {
        return Err(anyhow::anyhow!("max_hops must be > 0"));
    }

    let mut chain: Vec<String> = Vec::new();
    let mut current = start_url.to_string();

    for _ in 0..max_hops {
        chain.push(current.clone());
        // Add realistic browser headers to reduce bot detection during redirect resolution
        // This is critical because sites may serve different content (or block) based on headers
        let resp = RequestHeaders::apply_to_request_builder(client.get(&current))
            .send()
            .await?;

        // Only follow redirects if the status code indicates a redirect AND there's a Location header
        let status = resp.status();
        let status_code = status.as_u16();
        // Check if status is a redirect (301, 302, 303, 307, 308)
        if status_code == 301
            || status_code == 302
            || status_code == 303
            || status_code == 307
            || status_code == 308
        {
            if let Some(loc) = resp.headers().get(reqwest::header::LOCATION) {
                let loc = loc.to_str().unwrap_or("").to_string();
                let new_url = Url::parse(&loc)
                    .or_else(|_| Url::parse(&current).and_then(|base| base.join(&loc)))?;
                current = new_url.to_string();
                continue;
            } else {
                // Redirect status but no Location header - this is unusual, log and break
                log::warn!(
                    "Redirect status {} for {} but no Location header",
                    status_code,
                    current
                );
                break;
            }
        } else {
            // Not a redirect, we've reached the final URL
            // Ensure final URL is in the chain (it was added at the start of the loop)
            break;
        }
    }

    // Ensure final URL is included in chain (in case we broke out of loop)
    // The final URL is already in chain from the last iteration, but verify it's there
    if !chain.contains(&current) {
        chain.push(current.clone());
    }

    Ok((current, chain))
}
