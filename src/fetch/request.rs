//! HTTP request building and header extraction.
//!
//! This module provides utilities for constructing realistic HTTP requests
//! and extracting headers from responses.

use std::collections::HashMap;

/// Realistic browser request headers to reduce bot detection.
///
/// These headers mimic a modern Chrome browser to help avoid detection by header analysis.
/// Used consistently across all HTTP requests to maintain a realistic browser fingerprint.
///
/// # Why These Headers?
///
/// Modern bot detection systems analyze HTTP headers to identify automated requests.
/// By using realistic browser headers, we reduce the likelihood of being blocked:
///
/// - **Accept headers**: Match modern browser content negotiation
/// - **Accept-Language**: Indicates English-speaking user (common default)
/// - **Accept-Encoding**: Supports compression (gzip, deflate, brotli)
/// - **Referer**: Simulates navigation from Google (common entry point)
/// - **Sec-Fetch-***: Modern browser security headers (helps with some detection systems)
/// - **Upgrade-Insecure-Requests**: Indicates preference for HTTPS
/// - **Cache-Control**: Indicates fresh content request
///
/// # Note on TLS Fingerprinting
///
/// While these headers help with header-based detection, JA3 TLS fingerprinting will
/// still identify rustls. This is acceptable as many legitimate applications use rustls,
/// and the combination of realistic headers + reasonable rate limiting provides good
/// bot evasion for most use cases.
pub(crate) struct RequestHeaders;

impl RequestHeaders {
    /// Returns headers as a vector of (name, value) tuples for failure tracking.
    pub(crate) fn as_vec() -> Vec<(String, String)> {
        vec![
            (
                "accept".to_string(),
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".to_string(),
            ),
            ("accept-language".to_string(), "en-US,en;q=0.9".to_string()),
            ("accept-encoding".to_string(), "gzip, deflate, br".to_string()),
            ("referer".to_string(), "https://www.google.com/".to_string()),
            ("sec-fetch-dest".to_string(), "document".to_string()),
            ("sec-fetch-mode".to_string(), "navigate".to_string()),
            ("sec-fetch-site".to_string(), "none".to_string()),
            ("sec-fetch-user".to_string(), "?1".to_string()),
            ("upgrade-insecure-requests".to_string(), "1".to_string()),
            ("cache-control".to_string(), "max-age=0".to_string()),
        ]
    }

    /// Applies the standard request headers to a `reqwest::RequestBuilder`.
    ///
    /// This is the preferred method for building requests as it uses reqwest's
    /// header constants directly, avoiding string parsing overhead.
    pub(crate) fn apply_to_request_builder(
        builder: reqwest::RequestBuilder,
    ) -> reqwest::RequestBuilder {
        builder
            .header(
                reqwest::header::ACCEPT,
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            )
            .header(reqwest::header::ACCEPT_LANGUAGE, "en-US,en;q=0.9")
            .header(reqwest::header::ACCEPT_ENCODING, "gzip, deflate, br")
            .header(reqwest::header::REFERER, "https://www.google.com/")
            .header(
                reqwest::header::HeaderName::from_static("sec-fetch-dest"),
                "document",
            )
            .header(
                reqwest::header::HeaderName::from_static("sec-fetch-mode"),
                "navigate",
            )
            .header(
                reqwest::header::HeaderName::from_static("sec-fetch-site"),
                "none",
            )
            .header(
                reqwest::header::HeaderName::from_static("sec-fetch-user"),
                "?1",
            )
            .header(reqwest::header::UPGRADE_INSECURE_REQUESTS, "1")
            .header(reqwest::header::CACHE_CONTROL, "max-age=0")
    }
}

/// Extracts security headers from an HTTP response.
///
/// Uses the `SECURITY_HEADERS` list from `config.rs` to determine which headers to capture.
/// These headers are stored in the `url_security_headers` table.
///
/// Security headers captured include:
/// - Content-Security-Policy (CSP)
/// - X-Frame-Options
/// - X-Content-Type-Options
/// - Strict-Transport-Security (HSTS)
/// - Referrer-Policy
/// - Permissions-Policy
///
/// # Arguments
///
/// * `headers` - The HTTP response headers
///
/// # Returns
///
/// A map of header names to header values. Only headers that are present in the
/// response are included in the map.
pub fn extract_security_headers(
    headers: &reqwest::header::HeaderMap,
) -> HashMap<String, String> {
    crate::config::SECURITY_HEADERS
        .iter()
        .filter_map(|&header_name| {
            headers.get(header_name).map(|value| {
                (
                    header_name.to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
        })
        .collect()
}

/// Extracts other HTTP headers (non-security) from a response.
///
/// Uses the `HTTP_HEADERS` list from `config.rs` to determine which headers to capture.
/// These headers are stored in the `url_http_headers` table.
///
/// Headers captured include:
/// - Infrastructure: Server, X-Powered-By, X-Generator (technology detection)
/// - CDN/Proxy: CF-Ray, X-Served-By, Via (infrastructure analysis)
/// - Performance: Server-Timing, X-Cache (performance monitoring)
/// - Caching: Cache-Control, ETag, Last-Modified (cache analysis)
///
/// # Arguments
///
/// * `headers` - The HTTP response headers
///
/// # Returns
///
/// A map of header names to header values. Only headers that are present in the
/// response are included in the map.
pub fn extract_http_headers(headers: &reqwest::header::HeaderMap) -> HashMap<String, String> {
    crate::config::HTTP_HEADERS
        .iter()
        .filter_map(|&header_name| {
            headers.get(header_name).map(|value| {
                (
                    header_name.to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
        })
        .collect()
}

