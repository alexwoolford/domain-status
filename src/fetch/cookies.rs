//! Shared `Set-Cookie` / Cookie header parsing.
//!
//! One parse path feeds both storage [`CookieInfo`](crate::storage::CookieInfo)
//! (security attributes) and fingerprint name→value maps (lowercased).

use reqwest::header::HeaderMap;
use std::collections::HashMap;

use crate::storage::CookieInfo;

/// Intermediate parse of a single `Set-Cookie` header value.
struct ParsedSetCookie {
    name: String,
    /// Present when the cookie has a `name=value` form (`value` may be empty).
    /// Absent when the header is name-only (`session; Path=/`).
    value: Option<String>,
    secure: bool,
    http_only: bool,
    same_site: Option<String>,
    domain: Option<String>,
    path: Option<String>,
}

fn parse_set_cookie(s: &str) -> Option<ParsedSetCookie> {
    let parts: Vec<&str> = s.split(';').collect();
    let name_value = parts.first()?;
    let mut nv = name_value.splitn(2, '=');
    let name = nv.next()?.trim().to_string();
    if name.is_empty() {
        return None;
    }
    let value = nv.next().map(|v| v.trim().to_string());

    let lower = s.to_lowercase();
    let secure = lower.contains("secure");
    let http_only = lower.contains("httponly");
    let same_site = parts.iter().find_map(|p| {
        let p = p.trim().to_lowercase();
        if p.starts_with("samesite=") {
            Some(p.trim_start_matches("samesite=").trim().to_string())
        } else {
            None
        }
    });
    let domain = parts.iter().find_map(|p| {
        let p = p.trim();
        if p.to_lowercase().starts_with("domain=") {
            Some(p[7..].trim().to_string())
        } else {
            None
        }
    });
    let path = parts.iter().find_map(|p| {
        let p = p.trim();
        if p.to_lowercase().starts_with("path=") {
            Some(p[5..].trim().to_string())
        } else {
            None
        }
    });

    Some(ParsedSetCookie {
        name,
        value,
        secure,
        http_only,
        same_site,
        domain,
        path,
    })
}

fn parse_all_set_cookies(headers: &HeaderMap) -> Vec<ParsedSetCookie> {
    headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|val| val.to_str().ok())
        .filter_map(parse_set_cookie)
        .collect()
}

/// Parses `Set-Cookie` headers into [`CookieInfo`] structs for storage.
pub(crate) fn extract_cookie_infos(headers: &HeaderMap) -> Vec<CookieInfo> {
    parse_all_set_cookies(headers)
        .into_iter()
        .map(|c| CookieInfo {
            name: c.name,
            secure: c.secure,
            http_only: c.http_only,
            same_site: c.same_site,
            domain: c.domain,
            path: c.path,
        })
        .collect()
}

/// Extracts cookies for fingerprint matching (lowercased name→value).
///
/// Includes `Set-Cookie` response cookies and the request `Cookie` header.
/// Name-only `Set-Cookie` values (no `=`) are omitted from the map.
pub(crate) fn extract_cookies_name_value_map(headers: &HeaderMap) -> HashMap<String, String> {
    let mut cookies: HashMap<String, String> = parse_all_set_cookies(headers)
        .into_iter()
        .filter_map(|c| c.value.map(|v| (c.name.to_lowercase(), v.to_lowercase())))
        .collect();

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

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn test_extract_cookie_infos_attributes() {
        let mut headers = HeaderMap::new();
        headers.append(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict"),
        );

        let cookies = extract_cookie_infos(&headers);
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name, "session");
        assert!(cookies[0].secure);
        assert!(cookies[0].http_only);
        assert_eq!(cookies[0].same_site.as_deref(), Some("strict"));
        assert_eq!(cookies[0].path.as_deref(), Some("/"));
    }

    #[test]
    fn test_extract_cookies_name_value_map_set_cookie() {
        let mut headers = HeaderMap::new();
        headers.append(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("session=abc123; Path=/; HttpOnly"),
        );
        headers.append(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("theme=dark; Path=/"),
        );

        let cookies = extract_cookies_name_value_map(&headers);
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies.get("session"), Some(&"abc123".to_string()));
        assert_eq!(cookies.get("theme"), Some(&"dark".to_string()));
    }

    #[test]
    fn test_extract_cookies_name_value_map_cookie_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::COOKIE,
            HeaderValue::from_static("session=abc123; theme=dark"),
        );

        let cookies = extract_cookies_name_value_map(&headers);
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies.get("session"), Some(&"abc123".to_string()));
        assert_eq!(cookies.get("theme"), Some(&"dark".to_string()));
    }

    #[test]
    fn test_extract_cookies_name_value_map_case_insensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("Session=ABC123; Path=/"),
        );

        let cookies = extract_cookies_name_value_map(&headers);
        assert_eq!(cookies.get("session"), Some(&"abc123".to_string()));
        assert!(!cookies.contains_key("Session"));
    }

    #[test]
    fn test_extract_cookies_name_value_map_no_value() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("session; Path=/"),
        );

        let map = extract_cookies_name_value_map(&headers);
        assert!(map.is_empty());
        // Storage still records the name-only cookie.
        let infos = extract_cookie_infos(&headers);
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].name, "session");
    }

    #[test]
    fn test_extract_cookies_name_value_map_empty_value() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("session=; Path=/"),
        );

        let cookies = extract_cookies_name_value_map(&headers);
        assert_eq!(cookies.get("session"), Some(&"".to_string()));
    }
}
