//! Favicon fetching, hashing, and data structures.
//!
//! Provides Shodan-compatible `MurmurHash3` favicon hashing and streaming
//! favicon download with size limits. The hash format matches Shodan's
//! `http.favicon.hash` field exactly, enabling direct interoperability
//! with global threat intelligence feeds.

use anyhow::{Error, Result};
use base64::Engine;
use std::sync::Arc;

use crate::config::{FAVICON_FETCH_TIMEOUT_SECS, MAX_FAVICON_SIZE};
use crate::fetch::stream::{stream_bytes_with_limit, OnLimit, StreamBytesError};
use crate::security::validate_url_safe;

/// Favicon data ready for database insertion.
#[derive(Debug, Clone)]
pub(crate) struct FaviconData {
    pub favicon_url: String,
    pub hash: i32,
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
    let hash = murmur3_32_bytes(formatted.as_bytes());

    // Reinterpret u32 bits as i32 for Shodan compatibility (Shodan stores favicon hash as signed)
    #[allow(clippy::cast_possible_wrap)]
    let signed = hash as i32;
    signed
}

/// In-memory `murmur3_32` (seed 0). `Read` cannot fail on `Cursor<&[u8]>`.
fn murmur3_32_bytes(bytes: &[u8]) -> u32 {
    murmur3::murmur3_32(&mut std::io::Cursor::new(bytes), 0)
        .expect("in-memory Cursor read cannot fail")
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
                log::debug!("Favicon fetch failed for {current_url}: {e}");
                return Ok(None);
            }
            Err(_) => {
                log::debug!("Favicon fetch timed out for {current_url}");
                return Ok(None);
            }
        };

        let status = response.status();
        if status.is_redirection() {
            if let Some(location) = response.headers().get(reqwest::header::LOCATION) {
                let location_str = location.to_str().unwrap_or("").trim();
                if location_str.is_empty() {
                    log::debug!("Favicon redirect missing or invalid Location for {current_url}");
                    return Ok(None);
                }
                let resolved = url::Url::parse(&current_url)
                    .ok()
                    .and_then(|base| base.join(location_str).ok())
                    .map(|u| u.to_string());
                let Some(next_url) = resolved else {
                    log::debug!(
                        "Favicon redirect invalid Location for {current_url}: {location_str}"
                    );
                    return Ok(None);
                };
                if validate_url_safe(&next_url).is_err() {
                    log::debug!("Favicon redirect SSRF-unsafe target rejected: {next_url}");
                    return Ok(None);
                }
                log::debug!("Favicon following redirect {current_url} -> {next_url}");
                current_url = next_url;
                continue;
            }
        }

        if !status.is_success() {
            log::debug!("Favicon fetch returned {status} for {current_url}");
            return Ok(None);
        }

        // Stream with size cap; abort (drop favicon) if oversize.
        let streamed =
            match stream_bytes_with_limit(response, max_size, OnLimit::Abort, &current_url).await {
                Ok(s) => s,
                Err(StreamBytesError::LimitExceeded) => {
                    log::debug!(
                        "Favicon exceeds {}KB limit for {} (aborting)",
                        max_size / 1024,
                        current_url,
                    );
                    return Ok(None);
                }
                Err(e) => {
                    log::debug!("Favicon stream error for {current_url}: {e}");
                    return Ok(None);
                }
            };

        let buf = streamed.into_bytes();
        if buf.is_empty() {
            return Ok(None);
        }

        return Ok(Some(buf));
    }

    log::debug!("Favicon redirect loop limit ({MAX_FAVICON_REDIRECTS}) exceeded for {url}");
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
/// 4. Returns `FaviconData` with a Shodan-compatible hash.
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
            log::debug!("Favicon fetch error for {favicon_url}: {e}");
            return None;
        }
    };

    let hash = compute_shodan_favicon_hash(&bytes);

    Some(FaviconData { favicon_url, hash })
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
        #[allow(clippy::cast_possible_wrap)]
        let expected_hash = murmur3_32_bytes(formatted.as_bytes()) as i32;
        assert_eq!(compute_shodan_favicon_hash(bytes), expected_hash);
    }

    #[test]
    fn test_compute_shodan_favicon_hash_known_value() {
        // Golden values from murmur3 0.1 (Shodan `http.favicon.hash` / mmh3 seed 0
        // of Python `base64.encodebytes` output, matching our newline formatting).
        let bytes = b"\x00\x00\x01\x00";
        assert_eq!(compute_shodan_favicon_hash(bytes), -216_455_174);
        assert_eq!(compute_shodan_favicon_hash(b""), -1_840_324_437);
        assert_eq!(
            compute_shodan_favicon_hash(b"test favicon content"),
            549_458_447
        );
        let boundary_57: Vec<u8> = (0u8..57).collect();
        assert_eq!(compute_shodan_favicon_hash(&boundary_57), 459_585_070);
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
        #[allow(clippy::cast_possible_wrap)]
        let expected_hash = murmur3_32_bytes(formatted.as_bytes()) as i32;
        assert_eq!(compute_shodan_favicon_hash(&bytes), expected_hash);
    }

    #[test]
    fn test_compute_shodan_favicon_hash_empty() {
        // Empty raw bytes still hash the trailing newline of the formatted base64.
        assert_eq!(compute_shodan_favicon_hash(b""), -1_840_324_437);
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

    fn no_redirect_client() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client")
    }

    /// Manual hop loop calls `validate_url_safe`, which rejects loopback. Map
    /// RFC `example.com` to the mock so same-origin `Location` hops are allowed.
    fn example_com_client(server: &wiremock::MockServer) -> (reqwest::Client, String) {
        let addr = server.address();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .resolve("example.com", *addr)
            .build()
            .expect("client");
        (client, format!("http://example.com:{}", addr.port()))
    }

    /// Kills: `OnLimit::Abort` returning `Some` when the body is one byte over
    /// `max_size`, or dropping an exact-size body.
    #[tokio::test]
    async fn test_fetch_favicon_bytes_size_cap() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::path("/exact.ico"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(vec![1u8; 8]))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::path("/over.ico"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(vec![1u8; 9]))
            .mount(&server)
            .await;
        let client = no_redirect_client();
        let exact = fetch_favicon_bytes(&client, &format!("{}/exact.ico", server.uri()), 8)
            .await
            .expect("exact");
        assert_eq!(exact.as_deref(), Some(&[1u8; 8][..]));
        let over = fetch_favicon_bytes(&client, &format!("{}/over.ico", server.uri()), 8)
            .await
            .expect("over");
        assert_eq!(over, None, "one byte over max_size must abort");
    }

    /// Kills: following redirects automatically (or ignoring `Location`) so a
    /// same-origin 302 never yields the hop body.
    #[tokio::test]
    async fn test_fetch_favicon_bytes_follows_same_origin_redirect() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::path("/start.ico"))
            .respond_with(wiremock::ResponseTemplate::new(302).insert_header("Location", "/ok.ico"))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::path("/ok.ico"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(vec![9u8; 4]))
            .mount(&server)
            .await;
        let (client, origin) = example_com_client(&server);
        let got = fetch_favicon_bytes(&client, &format!("{origin}/start.ico"), 64)
            .await
            .expect("redirect hop");
        assert_eq!(got.as_deref(), Some(&[9u8; 4][..]));
    }

    /// Kills: following a redirect to `127.0.0.1` (SSRF hop must be `None`).
    /// Destination serves a body so a skipped `validate_url_safe` would yield `Some`.
    #[tokio::test]
    async fn test_fetch_favicon_bytes_rejects_ssrf_redirect() {
        let server = wiremock::MockServer::start().await;
        let stolen = format!("http://127.0.0.1:{}/stolen.ico", server.address().port());
        wiremock::Mock::given(wiremock::matchers::path("/favicon.ico"))
            .respond_with(
                wiremock::ResponseTemplate::new(302).insert_header("Location", stolen.as_str()),
            )
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::path("/stolen.ico"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(vec![3u8; 4]))
            .mount(&server)
            .await;
        let got = fetch_favicon_bytes(
            &no_redirect_client(),
            &format!("{}/favicon.ico", server.uri()),
            64,
        )
        .await
        .expect("ssrf hop");
        assert_eq!(got, None, "loopback redirect must be rejected");
    }

    /// Kills: raising `MAX_FAVICON_REDIRECTS` so a 6-hop chain still returns
    /// a body.
    #[tokio::test]
    async fn test_fetch_favicon_bytes_stops_after_five_redirects() {
        let server = wiremock::MockServer::start().await;
        for i in 0..6 {
            let path = format!("/h{i}");
            let next = format!("/h{}", i + 1);
            wiremock::Mock::given(wiremock::matchers::path(path.as_str()))
                .respond_with(wiremock::ResponseTemplate::new(302).insert_header("Location", next))
                .mount(&server)
                .await;
        }
        wiremock::Mock::given(wiremock::matchers::path("/h6"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(vec![7u8; 4]))
            .mount(&server)
            .await;
        let (client, origin) = example_com_client(&server);
        let got = fetch_favicon_bytes(&client, &format!("{origin}/h0"), 64)
            .await
            .expect("loop");
        assert_eq!(got, None, "six 302 hops must exceed the redirect cap");
    }
}
