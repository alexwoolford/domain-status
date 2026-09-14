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
    let mut parts = s.split(';');
    let name_value = parts.next()?;
    let mut nv = name_value.splitn(2, '=');
    let name = nv.next()?.trim().to_string();
    if name.is_empty() {
        return None;
    }
    let value = nv.next().map(|v| v.trim().to_string());

    let mut secure = false;
    let mut http_only = false;
    let mut same_site = None;
    let mut same_site_invalid = false;
    let mut domain = None;
    let mut path = None;
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (attr_name, attr_value) = match part.split_once('=') {
            Some((n, v)) => (n.trim(), Some(v.trim())),
            None => (part, None),
        };
        if attr_name.eq_ignore_ascii_case("secure") {
            secure = true;
        } else if attr_name.eq_ignore_ascii_case("httponly") {
            http_only = true;
        } else if attr_name.eq_ignore_ascii_case("samesite") {
            match attr_value.and_then(allowlisted_same_site) {
                Some(value) if same_site.is_none() && !same_site_invalid => {
                    same_site = Some(value);
                }
                None => {
                    // Comma-jammed or otherwise non-allowlisted tokens (e.g.
                    // `SameSite=Lax, b=2`) must not let a later `SameSite=None`
                    // from a concatenated second cookie win.
                    same_site = None;
                    same_site_invalid = true;
                }
                Some(_) => {}
            }
        } else if attr_name.eq_ignore_ascii_case("domain") {
            domain = attr_value
                .filter(|v| !v.is_empty())
                .map(std::string::ToString::to_string);
        } else if attr_name.eq_ignore_ascii_case("path") {
            path = attr_value.map(std::string::ToString::to_string);
        }
    }

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

/// RFC 6265bis `SameSite`: only `Strict` / `Lax` / `None` (stored lowercase).
fn allowlisted_same_site(raw: &str) -> Option<String> {
    let token = raw.trim();
    if token.eq_ignore_ascii_case("strict") {
        Some("strict".to_string())
    } else if token.eq_ignore_ascii_case("lax") {
        Some("lax".to_string())
    } else if token.eq_ignore_ascii_case("none") {
        Some("none".to_string())
    } else {
        None
    }
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

    #[test]
    fn test_extract_cookie_infos_samesite_allowlist() {
        let mut headers = HeaderMap::new();
        headers.append(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("a=1; SameSite=Lax"),
        );
        headers.append(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("b=1; SameSite=NONE"),
        );
        headers.append(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("c=1; SameSite=true"),
        );
        headers.append(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("d=1; SameSite=1"),
        );
        headers.append(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("e=1; SameSite=stric"),
        );

        let cookies = extract_cookie_infos(&headers);
        assert_eq!(cookies.len(), 5);
        assert_eq!(cookies[0].same_site.as_deref(), Some("lax"));
        assert_eq!(cookies[1].same_site.as_deref(), Some("none"));
        assert_eq!(cookies[2].same_site, None);
        assert_eq!(cookies[3].same_site, None);
        assert_eq!(cookies[4].same_site, None);
    }

    #[test]
    fn test_extract_cookie_infos_concatenated_set_cookie() {
        let mut headers = HeaderMap::new();
        headers.append(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("session=abc123; Path=/; SameSite=Strict"),
        );
        headers.append(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("theme=dark; Path=/; SameSite=Lax"),
        );

        let cookies = extract_cookie_infos(&headers);
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[0].same_site.as_deref(), Some("strict"));
        assert_eq!(cookies[1].same_site.as_deref(), Some("lax"));

        let mut jammed = HeaderMap::new();
        jammed.append(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("a=1; Path=/; SameSite=Lax, b=2; SameSite=None"),
        );
        let jammed_cookies = extract_cookie_infos(&jammed);
        assert_eq!(jammed_cookies.len(), 1);
        assert_eq!(
            jammed_cookies[0].same_site, None,
            "comma-concatenated SameSite token is not an allowlisted value"
        );
    }

    #[test]
    fn test_extract_cookie_infos_secure_httponly_are_attribute_tokens() {
        let mut headers = HeaderMap::new();
        headers.append(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("session=abc; Path=/insecure; Domain=httponly.example"),
        );

        let cookies = extract_cookie_infos(&headers);
        assert_eq!(cookies.len(), 1);
        assert!(
            !cookies[0].secure,
            "Path=/insecure must not set the Secure flag"
        );
        assert!(
            !cookies[0].http_only,
            "Domain containing httponly must not set HttpOnly"
        );
        assert_eq!(cookies[0].path.as_deref(), Some("/insecure"));

        let mut flagged = HeaderMap::new();
        flagged.append(
            reqwest::header::SET_COOKIE,
            HeaderValue::from_static("session=abc; Path=/; HttpOnly; Secure"),
        );
        let flagged_cookies = extract_cookie_infos(&flagged);
        assert!(flagged_cookies[0].secure);
        assert!(flagged_cookies[0].http_only);
    }
}
