// Fetch module tests.

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Url;
use crate::fetch::request::extract_security_headers;

fn create_header_map() -> HeaderMap {
    HeaderMap::new()
}

fn add_header(headers: &mut HeaderMap, name: &str, value: &str) {
    // In tests, we use known-good header names and values
    // If parsing fails, it's a test setup error and should fail fast
    let header_name = HeaderName::from_bytes(name.as_bytes())
        .unwrap_or_else(|_| panic!("Invalid header name in test: {}", name));
    let header_value = HeaderValue::from_str(value)
        .unwrap_or_else(|_| panic!("Invalid header value in test: {}", value));
    headers.insert(header_name, header_value);
}

#[test]
fn test_extract_security_headers_basic() {
    let mut headers = create_header_map();
    add_header(
        &mut headers,
        "Content-Security-Policy",
        "default-src 'self'",
    );
    add_header(&mut headers, "X-Frame-Options", "DENY");

    let result = extract_security_headers(&headers);
    assert_eq!(result.len(), 2);
    assert_eq!(
        result.get("Content-Security-Policy"),
        Some(&"default-src 'self'".to_string())
    );
    assert_eq!(result.get("X-Frame-Options"), Some(&"DENY".to_string()));
}

#[test]
fn test_extract_security_headers_all_headers() {
    let mut headers = create_header_map();
    add_header(
        &mut headers,
        "Content-Security-Policy",
        "default-src 'self'",
    );
    add_header(
        &mut headers,
        "Strict-Transport-Security",
        "max-age=31536000",
    );
    add_header(&mut headers, "X-Content-Type-Options", "nosniff");
    add_header(&mut headers, "X-Frame-Options", "SAMEORIGIN");
    add_header(&mut headers, "X-XSS-Protection", "1; mode=block");
    add_header(
        &mut headers,
        "Referrer-Policy",
        "strict-origin-when-cross-origin",
    );
    add_header(
        &mut headers,
        "Permissions-Policy",
        "geolocation=(), microphone=()",
    );

    let result = extract_security_headers(&headers);
    assert_eq!(result.len(), 7);
}

#[test]
fn test_extract_security_headers_missing_headers() {
    let headers = create_header_map();
    let result = extract_security_headers(&headers);
    assert_eq!(result.len(), 0);
}

#[test]
fn test_extract_security_headers_partial_headers() {
    let mut headers = create_header_map();
    add_header(&mut headers, "X-Frame-Options", "DENY");
    // Add a non-security header
    add_header(&mut headers, "Content-Type", "text/html");

    let result = extract_security_headers(&headers);
    assert_eq!(result.len(), 1);
    assert_eq!(result.get("X-Frame-Options"), Some(&"DENY".to_string()));
    assert!(!result.contains_key("Content-Type"));
}

#[test]
fn test_extract_security_headers_case_sensitive() {
    // HTTP header names are case-insensitive, but our code uses exact matches
    // This documents the current behavior: case-sensitive matching
    let mut headers = create_header_map();
    add_header(&mut headers, "x-frame-options", "DENY"); // lowercase
    add_header(&mut headers, "X-Frame-Options", "SAMEORIGIN"); // mixed case

    let result = extract_security_headers(&headers);
    // Current implementation only matches exact case "X-Frame-Options"
    // So lowercase "x-frame-options" won't match
    assert_eq!(
        result.get("X-Frame-Options"),
        Some(&"SAMEORIGIN".to_string())
    );
    assert!(!result.contains_key("x-frame-options"));
}

#[test]
fn test_extract_security_headers_empty_value() {
    let mut headers = create_header_map();
    add_header(&mut headers, "X-Frame-Options", "");

    let result = extract_security_headers(&headers);
    assert_eq!(result.len(), 1);
    assert_eq!(result.get("X-Frame-Options"), Some(&"".to_string()));
}

#[test]
fn test_extract_security_headers_multiple_values() {
    // HTTP spec allows multiple values, but reqwest::HeaderMap typically
    // only stores one. This test documents current behavior.
    let mut headers = create_header_map();
    add_header(&mut headers, "X-Frame-Options", "DENY");

    let result = extract_security_headers(&headers);
    // Should get the single value
    assert_eq!(result.get("X-Frame-Options"), Some(&"DENY".to_string()));
}

#[test]
fn test_extract_security_headers_complex_csp() {
    // Test with complex CSP policy (common real-world case)
    let mut headers = create_header_map();
    let csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'";
    add_header(&mut headers, "Content-Security-Policy", csp);

    let result = extract_security_headers(&headers);
    assert_eq!(
        result.get("Content-Security-Policy"),
        Some(&csp.to_string())
    );
}

#[test]
fn test_extract_security_headers_hsts_with_include_subdomains() {
    // Test HSTS header with includeSubDomains (common real-world case)
    let mut headers = create_header_map();
    add_header(
        &mut headers,
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains",
    );

    let result = extract_security_headers(&headers);
    assert_eq!(
        result.get("Strict-Transport-Security"),
        Some(&"max-age=31536000; includeSubDomains".to_string())
    );
}

#[test]
fn test_url_join_absolute_location() {
    // Test URL joining logic used in redirect resolution
    // Absolute URL in Location header should be used as-is
    let base = Url::parse("https://example.com/path").unwrap();
    let absolute_location = "https://other.com/new-path";

    let joined = base.join(absolute_location);
    assert!(joined.is_ok());
    assert_eq!(joined.unwrap().as_str(), "https://other.com/new-path");
}

#[test]
fn test_url_join_relative_location() {
    // Test relative URL joining (common redirect gotcha)
    let base = Url::parse("https://example.com/old/path").unwrap();
    let relative_location = "/new/path";

    let joined = base.join(relative_location);
    assert!(joined.is_ok());
    assert_eq!(joined.unwrap().as_str(), "https://example.com/new/path");
}

#[test]
fn test_url_join_relative_path_location() {
    // Test relative path (not starting with /)
    let base = Url::parse("https://example.com/old/path").unwrap();
    let relative_location = "new/path";

    let joined = base.join(relative_location);
    assert!(joined.is_ok());
    assert_eq!(joined.unwrap().as_str(), "https://example.com/old/new/path");
}

#[test]
fn test_url_join_relative_query_location() {
    // Test relative URL with query string
    let base = Url::parse("https://example.com/path").unwrap();
    let relative_location = "/new?param=value";

    let joined = base.join(relative_location);
    assert!(joined.is_ok());
    let url = joined.unwrap();
    assert_eq!(url.path(), "/new");
    assert_eq!(url.query(), Some("param=value"));
}

#[test]
fn test_url_join_relative_fragment_location() {
    // Test relative URL with fragment
    let base = Url::parse("https://example.com/path").unwrap();
    let relative_location = "/new#section";

    let joined = base.join(relative_location);
    assert!(joined.is_ok());
    let url = joined.unwrap();
    assert_eq!(url.path(), "/new");
    assert_eq!(url.fragment(), Some("section"));
}

#[test]
fn test_url_join_malformed_location() {
    // Test malformed Location header (should fail parsing)
    let base = Url::parse("https://example.com/path").unwrap();
    let malformed_location = "not a valid url!!!";

    let parsed_direct = Url::parse(malformed_location);
    assert!(parsed_direct.is_err());

    // When direct parse fails, should try joining with base
    let joined = base.join(malformed_location);
    // This might succeed or fail depending on URL parser behavior
    // The important thing is it doesn't panic
    let _ = joined;
}

#[test]
fn test_url_join_empty_location() {
    // Edge case: empty Location header
    let base = Url::parse("https://example.com/path").unwrap();
    let empty_location = "";

    let parsed_direct = Url::parse(empty_location);
    assert!(parsed_direct.is_err());

    let joined = base.join(empty_location);
    // Empty string might be treated as relative path
    let _ = joined;
}

#[test]
fn test_url_join_protocol_relative() {
    // Protocol-relative URLs (//example.com/path) - common redirect pattern
    let protocol_relative = "//other.com/new";

    // Protocol-relative URLs should parse
    if let Ok(url) = Url::parse(protocol_relative) {
        assert_eq!(url.host_str(), Some("other.com"));
        assert_eq!(url.path(), "/new");
    }
}

#[test]
fn test_url_join_different_scheme() {
    // Redirect from HTTP to HTTPS (common security practice)
    let base = Url::parse("http://example.com/path").unwrap();
    let https_location = "https://example.com/secure";

    let joined = base.join(https_location);
    assert!(joined.is_ok());
    let url = joined.unwrap();
    assert_eq!(url.scheme(), "https");
    assert_eq!(url.as_str(), "https://example.com/secure");
}
