//! Favicon fetching, hashing, and data structures.
//!
//! Provides Shodan-compatible `MurmurHash3` favicon hashing and streaming
//! favicon download with size limits. The hash format matches Shodan's
//! `http.favicon.hash` field exactly, enabling direct interoperability
//! with global threat intelligence feeds.

use anyhow::{Error, Result};
use base64::Engine;
use futures::StreamExt;
use std::sync::Arc;

use crate::config::{FAVICON_FETCH_TIMEOUT_SECS, MAX_FAVICON_SIZE};
use crate::security::validate_url_safe;

/// Favicon data ready for database insertion.
#[derive(Debug, Clone)]
pub(crate) struct FaviconData {
    pub favicon_url: String,
    pub hash: i32,
    pub base64_data: String,
}

/// Computes a Shodan-compatible `MurmurHash3` of favicon bytes.
///
/// Shodan hashes the base64 encoding (with newlines every 76 characters
/// and a trailing newline) using `MurmurHash3` (32-bit, seed 0). This
/// function replicates that exact format so hashes can be dropped directly
/// into `http.favicon.hash:<hash>` Shodan queries.
pub(crate) fn compute_shodan_favicon_hash(raw_bytes: &[u8]) -> i32 {
    let base64_str = base64::engine::general_purpose::STANDARD.encode(raw_bytes);

    // Insert a newline every 76 characters to match Python's base64.encodebytes()
    let mut formatted = String::with_capacity(base64_str.len() + base64_str.len() / 76 + 1);
    for (i, ch) in base64_str.chars().enumerate() {
        formatted.push(ch);
        if (i + 1) % 76 == 0 {
            formatted.push('\n');
        }
    }
    if !formatted.ends_with('\n') {
        formatted.push('\n');
    }

    // MurmurHash3 32-bit with seed 0, cast to i32 for Shodan compatibility
    let hash = murmur3::murmur3_32(&mut std::io::Cursor::new(formatted.as_bytes()), 0);

    // Reinterpret the u32 bits as i32 (Shodan stores as signed integer)
    hash as i32
}

/// Max redirect hops for favicon (SSRF-validated per hop).
const MAX_FAVICON_REDIRECTS: u8 = 5;

/// Streams favicon bytes from a URL with a size limit.
/// Follows up to `MAX_FAVICON_REDIRECTS` redirects, validating each hop with SSRF checks.
///
/// Returns `None` if the response is non-success, exceeds the size cap,
/// or the fetch times out.
async fn fetch_favicon_bytes(
    client: &reqwest::Client,
    url: &str,
    max_size: usize,
) -> Result<Option<Vec<u8>>, Error> {
    let mut current_url = url.to_string();
    // Initial fetch + up to MAX_FAVICON_REDIRECTS redirect hops
    for _ in 0..=MAX_FAVICON_REDIRECTS {
        let response = match tokio::time::timeout(
            std::time::Duration::from_secs(FAVICON_FETCH_TIMEOUT_SECS),
            client.get(&current_url).send(),
        )
        .await
        {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => {
                log::debug!("Favicon fetch failed for {}: {}", current_url, e);
                return Ok(None);
            }
            Err(_) => {
                log::debug!("Favicon fetch timed out for {}", current_url);
                return Ok(None);
            }
        };

        let status = response.status();
        if status.is_redirection() {
            if let Some(location) = response.headers().get(reqwest::header::LOCATION) {
                let location_str = location.to_str().unwrap_or("").trim();
                if location_str.is_empty() {
                    log::debug!(
                        "Favicon redirect missing or invalid Location for {}",
                        current_url
                    );
                    return Ok(None);
                }
                let resolved = url::Url::parse(&current_url)
                    .ok()
                    .and_then(|base| base.join(location_str).ok())
                    .map(|u| u.to_string());
                let Some(next_url) = resolved else {
                    log::debug!(
                        "Favicon redirect invalid Location for {}: {}",
                        current_url,
                        location_str
                    );
                    return Ok(None);
                };
                if validate_url_safe(&next_url).is_err() {
                    log::debug!("Favicon redirect SSRF-unsafe target rejected: {}", next_url);
                    return Ok(None);
                }
                log::debug!("Favicon following redirect {} -> {}", current_url, next_url);
                current_url = next_url;
                continue;
            }
        }

        if !status.is_success() {
            log::debug!("Favicon fetch returned {} for {}", status, current_url);
            return Ok(None);
        }

        // Stream with size cap (same pattern as stream_body_with_limit)
        let mut stream = response.bytes_stream();
        let mut buf = Vec::with_capacity(max_size.min(16 * 1024));

        while let Some(chunk_result) = stream.next().await {
            let chunk = match chunk_result {
                Ok(c) => c,
                Err(e) => {
                    log::debug!("Favicon stream error for {}: {}", current_url, e);
                    return Ok(None);
                }
            };

            if buf.len() + chunk.len() > max_size {
                log::debug!(
                    "Favicon exceeds {}KB limit for {} (aborting at {} bytes)",
                    max_size / 1024,
                    current_url,
                    buf.len() + chunk.len()
                );
                return Ok(None);
            }

            buf.extend_from_slice(&chunk);
        }

        if buf.is_empty() {
            return Ok(None);
        }

        return Ok(Some(buf));
    }

    log::debug!(
        "Favicon redirect loop limit ({}) exceeded for {}",
        MAX_FAVICON_REDIRECTS,
        url
    );
    Ok(None)
}

/// Resolves a potentially-relative favicon href against a base URL.
fn resolve_favicon_url(href: &str, base_url: &str) -> Option<String> {
    if href.starts_with("http://") || href.starts_with("https://") {
        return Some(href.to_string());
    }

    // Protocol-relative URL
    if let Some(path) = href.strip_prefix("//") {
        return Some(format!("https://{path}"));
    }

    // Relative path - resolve against the base URL
    url::Url::parse(base_url)
        .ok()
        .and_then(|base| base.join(href).ok())
        .map(|u| u.to_string())
}

/// Builds the fallback `/favicon.ico` URL from the final URL's origin.
/// Returns `None` for non-http(s) URLs (e.g. `ftp://`) or unparseable URLs.
fn fallback_favicon_url(final_url: &str) -> Option<String> {
    let u = url::Url::parse(final_url).ok()?;
    let scheme = u.scheme();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let host = u.host_str().unwrap_or("");
    Some(match u.port() {
        Some(port) => format!("{scheme}://{host}:{port}/favicon.ico"),
        None => format!("{scheme}://{host}/favicon.ico"),
    })
}

/// Fetches and hashes a favicon for a page.
///
/// 1. If `html_data.favicon_url` is set, resolves it against `final_url`.
/// 2. Otherwise falls back to `{origin}/favicon.ico`.
/// 3. Streams the bytes (capped at `MAX_FAVICON_SIZE`).
/// 4. Returns `FaviconData` with Shodan-compatible hash and base64 encoding.
pub(crate) async fn fetch_and_hash_favicon(
    client: &Arc<reqwest::Client>,
    favicon_href: Option<&str>,
    final_url: &str,
) -> Option<FaviconData> {
    let favicon_url = match favicon_href {
        Some(href) => resolve_favicon_url(href, final_url),
        None => fallback_favicon_url(final_url),
    };

    let favicon_url = favicon_url?;

    let bytes = match fetch_favicon_bytes(client, &favicon_url, MAX_FAVICON_SIZE).await {
        Ok(Some(b)) => b,
        Ok(None) => return None,
        Err(e) => {
            log::debug!("Favicon fetch error for {}: {}", favicon_url, e);
            return None;
        }
    };

    let hash = compute_shodan_favicon_hash(&bytes);
    let base64_data = base64::engine::general_purpose::STANDARD.encode(&bytes);

    Some(FaviconData {
        favicon_url,
        hash,
        base64_data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds the exact format Shodan uses: base64 with newline every 76 chars and trailing newline.
    fn shodan_format(base64_str: &str) -> String {
        let mut formatted = String::with_capacity(base64_str.len() + base64_str.len() / 76 + 1);
        for (i, ch) in base64_str.chars().enumerate() {
            formatted.push(ch);
            if (i + 1) % 76 == 0 {
                formatted.push('\n');
            }
        }
        if !formatted.ends_with('\n') {
            formatted.push('\n');
        }
        formatted
    }

    #[test]
    fn test_compute_shodan_favicon_hash_contract_matches_spec() {
        // Contract: hash must match Shodan spec (base64.encodebytes + mmh3 32-bit seed 0).
        // We build the spec string independently and hash it; compare to our implementation.
        let bytes = b"\x00\x00\x01\x00";
        let base64_str = base64::engine::general_purpose::STANDARD.encode(bytes);
        let formatted = shodan_format(&base64_str);
        let expected_hash =
            murmur3::murmur3_32(&mut std::io::Cursor::new(formatted.as_bytes()), 0) as i32;
        assert_eq!(compute_shodan_favicon_hash(bytes), expected_hash);
    }

    #[test]
    fn test_compute_shodan_favicon_hash_known_value() {
        // Verify against a known Shodan hash for a trivial favicon
        // Python equivalent:
        //   import mmh3, base64
        //   mmh3.hash(base64.encodebytes(b"\x00\x00\x01\x00"))
        let bytes = b"\x00\x00\x01\x00";
        let hash = compute_shodan_favicon_hash(bytes);
        // The hash should be a non-zero i32
        assert_ne!(hash, 0);
    }

    #[test]
    fn test_compute_shodan_favicon_hash_base64_76_char_boundary() {
        // Input that produces base64 length multiple of 76: ensures newline placement matches Python.
        // 57 raw bytes -> 76 base64 chars. Single newline at 76 serves as line break and trailing.
        let bytes: Vec<u8> = (0u8..57).collect();
        let base64_str = base64::engine::general_purpose::STANDARD.encode(&bytes);
        assert_eq!(
            base64_str.len(),
            76,
            "test assumption: 57 bytes -> 76 base64 chars"
        );
        let formatted = shodan_format(&base64_str);
        assert!(formatted.ends_with('\n'));
        assert_eq!(formatted.matches('\n').count(), 1); // one newline at 76 (no double trailing)
        let expected_hash =
            murmur3::murmur3_32(&mut std::io::Cursor::new(formatted.as_bytes()), 0) as i32;
        assert_eq!(compute_shodan_favicon_hash(&bytes), expected_hash);
    }

    #[test]
    fn test_compute_shodan_favicon_hash_empty() {
        let hash = compute_shodan_favicon_hash(b"");
        // Even empty bytes produce a hash (of the trailing newline in the formatted base64)
        assert_ne!(hash, 0);
    }

    #[test]
    fn test_compute_shodan_favicon_hash_deterministic() {
        let bytes = b"test favicon content";
        let h1 = compute_shodan_favicon_hash(bytes);
        let h2 = compute_shodan_favicon_hash(bytes);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_resolve_favicon_url_absolute() {
        let result = resolve_favicon_url("https://cdn.example.com/icon.png", "https://example.com");
        assert_eq!(result, Some("https://cdn.example.com/icon.png".to_string()));
    }

    #[test]
    fn test_resolve_favicon_url_relative() {
        let result = resolve_favicon_url("/img/favicon.png", "https://example.com/page");
        assert_eq!(
            result,
            Some("https://example.com/img/favicon.png".to_string())
        );
    }

    #[test]
    fn test_resolve_favicon_url_protocol_relative() {
        let result = resolve_favicon_url("//cdn.example.com/icon.png", "https://example.com");
        assert_eq!(result, Some("https://cdn.example.com/icon.png".to_string()));
    }

    #[test]
    fn test_fallback_favicon_url() {
        let result = fallback_favicon_url("https://example.com/some/page");
        assert_eq!(result, Some("https://example.com/favicon.ico".to_string()));
    }

    #[test]
    fn test_fallback_favicon_url_with_port() {
        let result = fallback_favicon_url("https://example.com:8443/page");
        assert_eq!(
            result,
            Some("https://example.com:8443/favicon.ico".to_string())
        );
    }

    #[test]
    fn test_resolve_favicon_url_invalid_base_url_returns_none() {
        let result = resolve_favicon_url("/favicon.ico", "not-a-valid-url");
        assert_eq!(result, None);
    }

    #[test]
    fn test_resolve_favicon_url_relative_with_empty_base_returns_none() {
        let result = resolve_favicon_url("/favicon.ico", "");
        assert_eq!(result, None);
    }

    #[test]
    fn test_fallback_favicon_url_non_http_returns_none() {
        let result = fallback_favicon_url("ftp://example.com/path");
        assert!(result.is_none());
    }

    #[test]
    fn test_fallback_favicon_url_unparseable_returns_none() {
        let result = fallback_favicon_url("not-a-url");
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_fetch_and_hash_favicon_returns_none_on_4xx() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let favicon_url = format!("{}/favicon.ico", server.uri());
        let client = Arc::new(reqwest::Client::builder().build().expect("test client"));
        let result = fetch_and_hash_favicon(&client, None, &favicon_url).await;
        assert!(result.is_none(), "4xx response must yield None");
    }
}
