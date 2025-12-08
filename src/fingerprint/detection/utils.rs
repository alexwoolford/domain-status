//! Header and cookie extraction utilities for technology detection.
//!
//! This module provides functions to extract and normalize headers and cookies
//! from HTTP responses for pattern matching.

use reqwest::header::HeaderMap;
use std::collections::HashMap;

/// Extracts cookies from HTTP headers (both SET_COOKIE and Cookie headers).
///
/// Normalizes cookie names and values to lowercase to match Go implementation.
pub(crate) fn extract_cookies_from_headers(headers: &HeaderMap) -> HashMap<String, String> {
    let mut cookies: HashMap<String, String> = headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|hv| hv.to_str().ok())
        .filter_map(|cookie_str| {
            cookie_str.split(';').next().and_then(|pair| {
                let mut parts = pair.splitn(2, '=');
                if let (Some(name), Some(value)) = (parts.next(), parts.next()) {
                    Some((name.trim().to_lowercase(), value.trim().to_lowercase()))
                } else {
                    None
                }
            })
        })
        .collect();

    // Also extract cookies from Cookie header (request cookies)
    if let Some(cookie_header) = headers.get(reqwest::header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie_pair in cookie_str.split(';') {
                let mut parts = cookie_pair.trim().splitn(2, '=');
                if let (Some(name), Some(value)) = (parts.next(), parts.next()) {
                    cookies.insert(name.trim().to_lowercase(), value.trim().to_lowercase());
                }
            }
        }
    }

    cookies
}

/// Converts HTTP headers to a lowercase map for pattern matching.
///
/// Normalizes both header names and values to lowercase to match Go implementation.
pub(crate) fn normalize_headers_to_map(headers: &HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_lowercase(), v.to_lowercase()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn test_extract_cookies_from_headers_set_cookie() {
        let mut headers = HeaderMap::new();
        // Use append() to add multiple SET_COOKIE headers (insert() replaces)
        headers.append(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("session=abc123; Path=/; HttpOnly"),
        );
        headers.append(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("theme=dark; Path=/"),
        );

        let cookies = extract_cookies_from_headers(&headers);
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies.get("session"), Some(&"abc123".to_string()));
        assert_eq!(cookies.get("theme"), Some(&"dark".to_string()));
    }

    #[test]
    fn test_extract_cookies_from_headers_cookie_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::COOKIE,
            HeaderValue::from_static("session=abc123; theme=dark"),
        );

        let cookies = extract_cookies_from_headers(&headers);
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies.get("session"), Some(&"abc123".to_string()));
        assert_eq!(cookies.get("theme"), Some(&"dark".to_string()));
    }

    #[test]
    fn test_extract_cookies_from_headers_both_sources() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("server_session=xyz789"),
        );
        headers.insert(
            reqwest::header::COOKIE,
            HeaderValue::from_static("client_session=abc123"),
        );

        let cookies = extract_cookies_from_headers(&headers);
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies.get("server_session"), Some(&"xyz789".to_string()));
        assert_eq!(cookies.get("client_session"), Some(&"abc123".to_string()));
    }

    #[test]
    fn test_extract_cookies_from_headers_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("Session=ABC123; Path=/"),
        );

        let cookies = extract_cookies_from_headers(&headers);
        // Should normalize to lowercase
        assert_eq!(cookies.get("session"), Some(&"abc123".to_string()));
        assert!(!cookies.contains_key("Session"));
    }

    #[test]
    fn test_extract_cookies_from_headers_empty_value() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("session=; Path=/"),
        );

        let cookies = extract_cookies_from_headers(&headers);
        assert_eq!(cookies.get("session"), Some(&"".to_string()));
    }

    #[test]
    fn test_extract_cookies_from_headers_no_value() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("session; Path=/"),
        );

        let cookies = extract_cookies_from_headers(&headers);
        // Cookie without value should not be extracted
        assert!(cookies.is_empty());
    }

    #[test]
    fn test_extract_cookies_from_headers_multiple_attributes() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict"),
        );

        let cookies = extract_cookies_from_headers(&headers);
        // Should only extract the first key=value pair, ignoring attributes
        assert_eq!(cookies.get("session"), Some(&"abc123".to_string()));
        assert_eq!(cookies.len(), 1);
    }

    #[test]
    fn test_extract_cookies_from_headers_empty() {
        let headers = HeaderMap::new();
        let cookies = extract_cookies_from_headers(&headers);
        assert!(cookies.is_empty());
    }

    #[test]
    fn test_normalize_headers_to_map() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::SERVER,
            HeaderValue::from_static("nginx/1.18.0"),
        );
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );

        let normalized = normalize_headers_to_map(&headers);
        assert_eq!(normalized.get("server"), Some(&"nginx/1.18.0".to_string()));
        assert_eq!(
            normalized.get("content-type"),
            Some(&"text/html; charset=utf-8".to_string())
        );
    }

    #[test]
    fn test_normalize_headers_to_map_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::SERVER,
            HeaderValue::from_static("NGINX/1.18.0"),
        );

        let normalized = normalize_headers_to_map(&headers);
        // Should normalize header name and value to lowercase
        assert_eq!(normalized.get("server"), Some(&"nginx/1.18.0".to_string()));
        assert!(!normalized.contains_key("SERVER"));
    }

    #[test]
    fn test_normalize_headers_to_map_invalid_utf8() {
        let mut headers = HeaderMap::new();
        // Create a header value that's not valid UTF-8
        let invalid_value = HeaderValue::from_bytes(&[0xFF, 0xFE, 0xFD]).unwrap();
        // Use a standard header name that exists
        headers.insert(reqwest::header::SERVER, invalid_value);

        let normalized = normalize_headers_to_map(&headers);
        // Invalid UTF-8 should be filtered out (to_str() fails)
        assert!(normalized.is_empty() || !normalized.contains_key("server"));
    }

    #[test]
    fn test_normalize_headers_to_map_empty() {
        let headers = HeaderMap::new();
        let normalized = normalize_headers_to_map(&headers);
        assert!(normalized.is_empty());
    }
}
