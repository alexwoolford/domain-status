//! HTTP redirect chain resolution.
//!
//! This module handles following redirect chains manually to track the full path
//! from initial URL to final destination.

use anyhow::{Error, Result};
use reqwest::Url;

use crate::fetch::request::RequestHeaders;

/// Checks if an HTTP status code indicates a redirect.
///
/// Returns `true` for redirect status codes: 301, 302, 303, 307, 308.
/// These are the standard HTTP redirect status codes that should be followed.
///
/// # Arguments
///
/// * `status_code` - The HTTP status code to check
///
/// # Returns
///
/// `true` if the status code is a redirect, `false` otherwise.
fn is_redirect_status(status_code: u16) -> bool {
    matches!(status_code, 301 | 302 | 303 | 307 | 308)
}

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

    // Pre-allocate chain with capacity to avoid reallocations
    let mut chain: Vec<String> = Vec::with_capacity(max_hops + 1);
    let mut current = start_url.to_string();

    for _ in 0..max_hops {
        // Clone current URL into chain (necessary since we'll modify current)
        chain.push(current.clone());
        // Add realistic browser headers to reduce bot detection during redirect resolution
        // This is critical because sites may serve different content (or block) based on headers
        // Note: We use GET instead of HEAD because:
        // 1. Some servers handle HEAD requests poorly (slower or reject them)
        // 2. The fallback overhead (HEAD -> GET) can add latency
        // 3. In practice, GET is often faster and more reliable for redirect resolution
        let resp = RequestHeaders::apply_to_request_builder(client.get(&current))
            .send()
            .await?;

        // Only follow redirects if the status code indicates a redirect AND there's a Location header
        let status = resp.status();
        let status_code = status.as_u16();
        // Check if status is a redirect (301, 302, 303, 307, 308)
        if is_redirect_status(status_code) {
            if let Some(loc) = resp.headers().get(reqwest::header::LOCATION) {
                // Avoid unnecessary String allocation - parse directly from &str
                // If header value is not valid UTF-8, skip this redirect (unusual but possible)
                let loc_str = match loc.to_str() {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!(
                            "Location header for {} contains invalid UTF-8: {}. Skipping redirect.",
                            current,
                            e
                        );
                        break;
                    }
                };
                let new_url = Url::parse(loc_str)
                    .or_else(|_| Url::parse(&current).and_then(|base| base.join(loc_str)))?;
                // Only allocate String when we actually need to update current
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
    let final_url = current.clone();
    if !chain.contains(&final_url) {
        chain.push(final_url.clone());
    }

    Ok((final_url, chain))
}

#[cfg(test)]
mod tests {
    use super::*;
    use httptest::{matchers::*, responders::*, Expectation, Server};

    #[tokio::test]
    async fn test_resolve_redirect_chain_no_redirects() {
        let server = Server::run();
        server.expect(
            Expectation::matching(request::method_path("GET", "/"))
                .respond_with(status_code(200).body("OK")),
        );

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let url = server.url("/").to_string();
        let (final_url, chain) = resolve_redirect_chain(&url, 10, &client).await.unwrap();

        assert_eq!(final_url, url);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0], url);
    }

    #[tokio::test]
    async fn test_resolve_redirect_chain_single_redirect() {
        let server = Server::run();
        let final_url = server.url("/final").to_string();

        server.expect(
            Expectation::matching(request::method_path("GET", "/")).respond_with(
                status_code(302)
                    .insert_header("Location", final_url.as_str())
                    .body("Redirect"),
            ),
        );
        server.expect(
            Expectation::matching(request::method_path("GET", "/final"))
                .respond_with(status_code(200).body("OK")),
        );

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let start_url = server.url("/").to_string();
        let (result_final, chain) = resolve_redirect_chain(&start_url, 10, &client)
            .await
            .unwrap();

        assert_eq!(result_final, final_url);
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0], start_url);
        assert_eq!(chain[1], final_url);
    }

    #[tokio::test]
    async fn test_resolve_redirect_chain_max_hops() {
        let server = Server::run();
        let url1 = server.url("/1").to_string();
        let url2 = server.url("/2").to_string();

        server.expect(
            Expectation::matching(request::method_path("GET", "/")).respond_with(
                status_code(302)
                    .insert_header("Location", url1.as_str())
                    .body("Redirect"),
            ),
        );
        server.expect(
            Expectation::matching(request::method_path("GET", "/1")).respond_with(
                status_code(302)
                    .insert_header("Location", url2.as_str())
                    .body("Redirect"),
            ),
        );

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let start_url = server.url("/").to_string();
        // Max hops = 2, so we do 2 iterations:
        // Iteration 1: Add start_url, request, redirect to url1, current = url1
        // Iteration 2: Add url1, request, redirect to url2, current = url2
        // After loop: url2 is not in chain, so we add it
        // Result: chain has 3 URLs (start_url, url1, url2), final = url2
        let (result_final, chain) = resolve_redirect_chain(&start_url, 2, &client)
            .await
            .unwrap();

        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0], start_url);
        assert_eq!(chain[1], url1);
        assert_eq!(chain[2], url2);
        assert_eq!(result_final, url2);
    }

    #[tokio::test]
    async fn test_resolve_redirect_chain_max_hops_zero() {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let result = resolve_redirect_chain("https://example.com", 0, &client).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("max_hops must be > 0"));
    }

    #[tokio::test]
    async fn test_resolve_redirect_chain_relative_location() {
        let server = Server::run();
        let final_url = server.url("/final").to_string();

        server.expect(
            Expectation::matching(request::method_path("GET", "/start")).respond_with(
                status_code(302)
                    .insert_header("Location", "/final") // Relative URL
                    .body("Redirect"),
            ),
        );
        server.expect(
            Expectation::matching(request::method_path("GET", "/final"))
                .respond_with(status_code(200).body("OK")),
        );

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let start_url = server.url("/start").to_string();
        let (result_final, chain) = resolve_redirect_chain(&start_url, 10, &client)
            .await
            .unwrap();

        assert_eq!(result_final, final_url);
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0], start_url);
        assert_eq!(chain[1], final_url);
    }

    #[tokio::test]
    async fn test_resolve_redirect_chain_redirect_without_location() {
        let server = Server::run();

        server.expect(
            Expectation::matching(request::method_path("GET", "/"))
                .respond_with(status_code(302).body("Redirect but no Location")),
        );

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let start_url = server.url("/").to_string();
        // Should break out of loop when redirect status but no Location header
        let (result_final, chain) = resolve_redirect_chain(&start_url, 10, &client)
            .await
            .unwrap();

        // Should include the start URL in chain, but not follow redirect
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0], start_url);
        assert_eq!(result_final, start_url);
    }

    #[tokio::test]
    async fn test_resolve_redirect_chain_different_redirect_codes() {
        let server = Server::run();
        let final_url = server.url("/final").to_string();

        // Test 301 (Moved Permanently)
        server.expect(
            Expectation::matching(request::method_path("GET", "/301")).respond_with(
                status_code(301)
                    .insert_header("Location", final_url.as_str())
                    .body("Moved"),
            ),
        );
        server.expect(
            Expectation::matching(request::method_path("GET", "/final"))
                .respond_with(status_code(200).body("OK")),
        );

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let start_url = server.url("/301").to_string();
        let (result_final, chain) = resolve_redirect_chain(&start_url, 10, &client)
            .await
            .unwrap();

        assert_eq!(result_final, final_url);
        assert_eq!(chain.len(), 2);
    }
}
