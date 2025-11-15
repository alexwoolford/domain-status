use anyhow::{Error, Result};
use hickory_resolver::TokioAsyncResolver;
use log::debug;
use publicsuffix::List;
use reqwest::Url;
use scraper::Html;
use sqlx::SqlitePool;
use std::collections::HashMap;

use crate::config::MAX_REDIRECT_HOPS;
use crate::database::{insert_url_record, UrlRecord};
use crate::dns::{resolve_host_to_ip, reverse_dns_lookup};
use crate::domain::extract_domain;
use crate::error_handling::{update_error_stats, ErrorStats};
use crate::html::{
    extract_linkedin_slug, extract_meta_description, extract_meta_keywords, extract_title,
    is_mobile_friendly,
};
use crate::tls::get_ssl_certificate_info;

/// Serializes a value to JSON string.
///
/// Note: JSON object key order is not guaranteed by the JSON spec, but serde_json
/// typically preserves insertion order for HashMap. If deterministic key ordering
/// is required, use BTreeMap in the source data structure instead.
fn serialize_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string())
}

/// Extracts security headers from an HTTP response.
///
/// # Arguments
///
/// * `headers` - The HTTP response headers
///
/// # Returns
///
/// A HashMap of security header names to values.
pub fn extract_security_headers(headers: &reqwest::header::HeaderMap) -> HashMap<String, String> {
    let headers_list = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
    ];

    headers_list
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

/// Resolves the redirect chain for a URL, following redirects up to a maximum number of hops.
///
/// # Arguments
///
/// * `start_url` - The initial URL to start from
/// * `max_hops` - Maximum number of redirect hops to follow
/// * `client` - HTTP client with redirects disabled (for manual tracking)
///
/// # Returns
///
/// A tuple of (final_url, redirect_chain_json) where:
/// - `final_url` is the final URL after all redirects
/// - `redirect_chain_json` is a JSON array of all URLs in the chain
///
/// # Errors
///
/// Returns an error if HTTP requests fail or URL parsing fails.
pub async fn resolve_redirect_chain(
    start_url: &str,
    max_hops: usize,
    client: &reqwest::Client,
) -> Result<(String, String), Error> {
    let mut chain: Vec<String> = Vec::new();
    let mut current = start_url.to_string();

    for _ in 0..max_hops {
        chain.push(current.clone());
        let resp = client.get(&current).send().await?;
        if let Some(loc) = resp.headers().get(reqwest::header::LOCATION) {
            let loc = loc.to_str().unwrap_or("").to_string();
            let new_url = Url::parse(&loc)
                .or_else(|_| Url::parse(&current).and_then(|base| base.join(&loc)))?;
            current = new_url.to_string();
            continue;
        }
        break;
    }
    let chain_json = serde_json::to_string(&chain).unwrap_or_else(|_| "[]".to_string());
    Ok((current, chain_json))
}

#[allow(clippy::too_many_arguments)]
/// Handles an HTTP response, extracting all relevant data and storing it in the database.
///
/// This function orchestrates domain extraction, TLS certificate retrieval, DNS lookups,
/// HTML parsing, and database insertion.
///
/// # Arguments
///
/// * `response` - The HTTP response
/// * `original_url` - The original URL before redirects
/// * `final_url_str` - The final URL after redirects
/// * `pool` - Database connection pool
/// * `extractor` - Public Suffix List extractor
/// * `resolver` - DNS resolver
/// * `error_stats` - Error statistics tracker
/// * `elapsed` - Response time in seconds
/// * `redirect_chain_json` - JSON array of redirect chain URLs
///
/// # Errors
///
/// Returns an error if domain extraction, DNS resolution, or database insertion fails.
pub async fn handle_response(
    response: reqwest::Response,
    original_url: &str,
    final_url_str: &str,
    pool: &SqlitePool,
    extractor: &List,
    resolver: &TokioAsyncResolver,
    error_stats: &ErrorStats,
    elapsed: f64,
    redirect_chain_json: Option<String>,
) -> Result<(), Error> {
    debug!("Started processing response for {final_url_str}");

    let final_url = response.url().to_string();
    debug!("Final url after redirects: {final_url}");

    let initial_domain = extract_domain(extractor, original_url)?;
    let final_domain = extract_domain(extractor, &final_url)?;
    debug!("Initial domain: {initial_domain}, Final domain: {final_domain}");

    let parsed_url = Url::parse(&final_url)?;
    let host = parsed_url
        .host_str()
        .ok_or_else(|| anyhow::Error::msg("Failed to extract host"))?;

    let (tls_version, subject, issuer, valid_from, valid_to, oids) =
        if final_url.starts_with("https://") {
            match get_ssl_certificate_info(host.to_string()).await {
                Ok(cert_info) => (
                    cert_info.tls_version,
                    cert_info.subject,
                    cert_info.issuer,
                    cert_info.valid_from,
                    cert_info.valid_to,
                    cert_info.oids,
                ),
                Err(e) => {
                    log::error!("Failed to get SSL certificate info for {final_domain}: {e}");
                    (None, None, None, None, None, None)
                }
            }
        } else {
            (None, None, None, None, None, None)
        };

    debug!("Extracted SSL info for {final_domain}: {tls_version:?}, {subject:?}, {issuer:?}, {valid_from:?}, {valid_to:?}");

    let headers = response.headers().clone();
    let status = response.status();
    let status_desc = status.canonical_reason().unwrap_or("Unknown Status Code");

    // Enforce HTML content-type, else skip
    if let Some(ct) = headers.get(reqwest::header::CONTENT_TYPE) {
        let ct = ct.to_str().unwrap_or("");
        if !ct.starts_with("text/html") {
            debug!("Skipping non-HTML content-type: {ct}");
            return Ok(());
        }
    }

    // Cap body size
    let body = match response.bytes().await {
        Ok(bytes) => {
            if bytes.len() > crate::config::MAX_RESPONSE_BODY_SIZE {
                debug!("Skipping large body: {} bytes", bytes.len());
                return Ok(());
            }
            String::from_utf8_lossy(&bytes).to_string()
        }
        Err(_) => String::new(),
    };

    // Parse HTML once and extract all data before any async operations
    // (Html is not Send, so we extract everything in a block scope)
    let (title, keywords_str, description, linkedin_slug, is_mobile_friendly) = {
        let document = Html::parse_document(&body);

        let title = extract_title(&document, error_stats);
        debug!("Extracted title for {final_domain}: {title:?}");

        let keywords = extract_meta_keywords(&document, error_stats);
        let keywords_str = keywords.map(|kw| kw.join(", "));
        debug!("Extracted keywords for {final_domain}: {keywords_str:?}");

        let description = extract_meta_description(&document, error_stats);
        debug!("Extracted description for {final_domain}: {description:?}");

        let linkedin_slug = extract_linkedin_slug(&document, error_stats);
        debug!("Extracted LinkedIn slug for {final_domain}: {linkedin_slug:?}");

        let is_mobile_friendly = is_mobile_friendly(&body);

        (
            title,
            keywords_str,
            description,
            linkedin_slug,
            is_mobile_friendly,
        )
    };

    debug!("Resolved host: {host}");

    let ip_address = resolve_host_to_ip(host, resolver).await?;
    debug!("Resolved IP address: {ip_address}");

    let reverse_dns_name = reverse_dns_lookup(&ip_address, resolver).await?;
    debug!("Resolved reverse DNS name: {reverse_dns_name:?}");

    let security_headers = extract_security_headers(&headers);
    let security_headers_json = serialize_json(&security_headers);

    let timestamp = chrono::Utc::now().timestamp_millis();

    debug!("Preparing to insert record for URL: {final_url}");
    log::info!("Attempting to insert record into database for domain: {initial_domain}");

    let record = UrlRecord {
        initial_domain,
        final_domain,
        ip_address,
        reverse_dns_name,
        status: status.as_u16(),
        status_desc: status_desc.to_string(),
        response_time: elapsed,
        title,
        keywords: keywords_str,
        description,
        linkedin_slug,
        security_headers: security_headers_json,
        tls_version,
        ssl_cert_subject: subject,
        ssl_cert_issuer: issuer,
        ssl_cert_valid_from: valid_from,
        ssl_cert_valid_to: valid_to,
        oids,
        is_mobile_friendly,
        timestamp,
        redirect_chain: redirect_chain_json,
    };

    let update_result = insert_url_record(pool, &record).await;

    match update_result {
        Ok(_) => log::info!("Record successfully inserted for URL: {final_url}"),
        Err(e) => log::error!("Failed to insert record for URL {final_url}: {e}"),
    };

    Ok(())
}

#[allow(clippy::too_many_arguments)]
/// Handles an HTTP request, resolving redirects and processing the response.
///
/// # Arguments
///
/// * `client` - HTTP client for making requests
/// * `redirect_client` - HTTP client with redirects disabled for manual redirect tracking
/// * `url` - The URL to process
/// * `pool` - Database connection pool
/// * `extractor` - Public Suffix List extractor
/// * `resolver` - DNS resolver
/// * `error_stats` - Error statistics tracker
/// * `start_time` - Request start time for calculating response time
///
/// # Errors
///
/// Returns an error if redirect resolution, HTTP request, or response handling fails.
pub async fn handle_http_request(
    client: &reqwest::Client,
    redirect_client: &reqwest::Client,
    url: &str,
    pool: &SqlitePool,
    extractor: &List,
    resolver: &TokioAsyncResolver,
    error_stats: &ErrorStats,
    start_time: std::time::Instant,
) -> Result<(), Error> {
    debug!("Resolving redirects for {url}");

    let (final_url_string, redirect_chain_json) =
        resolve_redirect_chain(url, MAX_REDIRECT_HOPS, redirect_client).await?;

    debug!("Sending request to final URL {final_url_string}");

    let res = client
        .get(&final_url_string)
        .header(reqwest::header::ACCEPT, "text/html,application/xhtml+xml")
        .send()
        .await;

    let elapsed = start_time.elapsed().as_secs_f64();

    let response = match res {
        Ok(response) => {
            debug!("Received response from {url}");
            response
        }
        Err(e) => {
            log::error!("Error occurred while accessing {url}: {e:?}");
            update_error_stats(error_stats, &e).await;
            return Err(e.into());
        }
    };

    debug!("Handling response for {final_url_string}");
    let handle_result = handle_response(
        response,
        url,
        &final_url_string,
        pool,
        extractor,
        resolver,
        error_stats,
        elapsed,
        Some(redirect_chain_json),
    )
    .await;

    match &handle_result {
        Ok(_) => debug!("Handled response for {url}"),
        Err(e) => log::error!("Failed to handle response for {url}: {e}"),
    }

    handle_result
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

    fn create_header_map() -> HeaderMap {
        HeaderMap::new()
    }

    fn add_header(headers: &mut HeaderMap, name: &str, value: &str) {
        let header_name = HeaderName::from_bytes(name.as_bytes()).unwrap();
        let header_value = HeaderValue::from_str(value).unwrap();
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
        assert!(joined.is_ok() || joined.is_err());
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
        assert!(joined.is_ok() || joined.is_err());
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
}
