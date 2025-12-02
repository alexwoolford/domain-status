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

