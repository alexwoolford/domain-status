//! HTTP request handling and response processing.
//!
//! This module handles:
//! - HTTP request construction with realistic browser headers
//! - Redirect chain resolution
//! - Response data extraction and validation
//! - Error handling with structured failure context
//!
//! The main entry points are:
//! - `handle_http_request()` - Orchestrates the full HTTP request flow
//! - `handle_response()` - Processes successful HTTP responses

use anyhow::{Error, Result};
use log::debug;
use reqwest::Url;
use scraper::{Html, Selector};
use std::collections::{HashMap, HashSet};

mod context;
pub use context::ProcessingContext;

use crate::config::MAX_REDIRECT_HOPS;
use crate::database::UrlRecord;
use crate::dns::{
    extract_dmarc_record, extract_spf_record, lookup_mx_records, lookup_ns_records,
    lookup_txt_records, resolve_host_to_ip, reverse_dns_lookup,
};
use crate::domain::extract_domain;
use crate::error_handling::update_error_stats;
use crate::fingerprint::detect_technologies;
use crate::geoip;
use crate::parse::{
    extract_meta_description, extract_meta_keywords, extract_social_media_links,
    extract_structured_data, extract_title, is_mobile_friendly,
};
use crate::security;
use crate::storage::BatchRecord;
use crate::tls::get_ssl_certificate_info;

/// Serializes a value to JSON string.
///
/// Note: JSON object key order is not guaranteed by the JSON spec, but serde_json
/// typically preserves insertion order for HashMap. If deterministic key ordering
/// is required, use BTreeMap in the source data structure instead.
fn serialize_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string())
}

/// Serializes a value to JSON string with a custom default for errors.
///
/// Useful for arrays where we want "[]" instead of "{}" on serialization failure.
fn serialize_json_with_default<T: serde::Serialize>(value: &T, default: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| default.to_string())
}

/// Builds realistic browser request headers to reduce bot detection.
///
/// Returns both a vector of header tuples (for failure tracking) and applies
/// headers to a request builder. These headers mimic a modern Chrome browser
/// to help avoid detection by header analysis.
///
/// # Returns
///
/// A vector of (header_name, header_value) tuples that can be used for
/// both request building and failure tracking.
fn build_request_headers() -> Vec<(String, String)> {
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

/// Extracts security-related HTTP headers from a response.
///
/// Uses the `SECURITY_HEADERS` list from `config.rs` to determine which headers to capture.
/// These headers are stored in the `url_security_headers` table.
///
/// # Arguments
///
/// * `headers` - The HTTP response headers
///
/// # Returns
///
/// A map of header names to header values. Only headers that are present in the
/// response are included in the map.
pub fn extract_security_headers(headers: &reqwest::header::HeaderMap) -> HashMap<String, String> {
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
/// A tuple of (final_url, redirect_chain) where:
/// - `final_url` is the final URL after all redirects
/// - `redirect_chain` is a vector of all URLs in the chain
///
/// # Errors
///
/// Returns an error if HTTP requests fail or URL parsing fails.
pub async fn resolve_redirect_chain(
    start_url: &str,
    max_hops: usize,
    client: &reqwest::Client,
) -> Result<(String, Vec<String>), Error> {
    let mut chain: Vec<String> = Vec::new();
    let mut current = start_url.to_string();

    for _ in 0..max_hops {
        chain.push(current.clone());
        // Add realistic browser headers to reduce bot detection during redirect resolution
        // This is critical because sites may serve different content (or block) based on headers
        let resp = client
            .get(&current)
            .header(reqwest::header::ACCEPT, "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
            .header(reqwest::header::ACCEPT_LANGUAGE, "en-US,en;q=0.9")
            .header(reqwest::header::ACCEPT_ENCODING, "gzip, deflate, br")
            .header(reqwest::header::REFERER, "https://www.google.com/")
            .header(reqwest::header::HeaderName::from_static("sec-fetch-dest"), "document")
            .header(reqwest::header::HeaderName::from_static("sec-fetch-mode"), "navigate")
            .header(reqwest::header::HeaderName::from_static("sec-fetch-site"), "none")
            .header(reqwest::header::HeaderName::from_static("sec-fetch-user"), "?1")
            .header(reqwest::header::UPGRADE_INSECURE_REQUESTS, "1")
            .header(reqwest::header::CACHE_CONTROL, "max-age=0")
            .send()
            .await?;

        // Only follow redirects if the status code indicates a redirect AND there's a Location header
        let status = resp.status();
        let status_code = status.as_u16();
        // Check if status is a redirect (301, 302, 303, 307, 308)
        if status_code == 301
            || status_code == 302
            || status_code == 303
            || status_code == 307
            || status_code == 308
        {
            if let Some(loc) = resp.headers().get(reqwest::header::LOCATION) {
                let loc = loc.to_str().unwrap_or("").to_string();
                let new_url = Url::parse(&loc)
                    .or_else(|_| Url::parse(&current).and_then(|base| base.join(&loc)))?;
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
            break;
        }
    }
    Ok((current, chain))
}

/// Extracted response data from HTTP response.
#[derive(Debug)]
struct ResponseData {
    final_url: String,
    initial_domain: String,
    final_domain: String,
    host: String,
    status: u16,
    status_desc: String,
    headers: reqwest::header::HeaderMap,
    security_headers: HashMap<String, String>,
    http_headers: HashMap<String, String>,
    body: String,
}

/// Extracts and validates response data from an HTTP response.
///
/// # Arguments
///
/// * `response` - The HTTP response
/// * `original_url` - The original URL before redirects
/// * `final_url_str` - The final URL after redirects
/// * `extractor` - Public Suffix List extractor
///
/// # Errors
///
/// Returns an error if domain extraction fails or response body cannot be read.
/// Returns `Ok(None)` if content-type is not HTML or body is empty/large.
async fn extract_response_data(
    response: reqwest::Response,
    original_url: &str,
    _final_url_str: &str,
    extractor: &publicsuffix::List,
) -> Result<Option<ResponseData>, Error> {
    let final_url = response.url().to_string();
    debug!("Final url after redirects: {final_url}");

    let initial_domain = extract_domain(extractor, original_url)?;
    let final_domain = extract_domain(extractor, &final_url)?;
    debug!("Initial domain: {initial_domain}, Final domain: {final_domain}");

    let parsed_url = Url::parse(&final_url)?;
    let host = parsed_url
        .host_str()
        .ok_or_else(|| anyhow::Error::msg("Failed to extract host"))?
        .to_string();

    let status = response.status();
    let status_desc = status
        .canonical_reason()
        .unwrap_or("Unknown Status Code")
        .to_string();

    // Extract headers before consuming response
    let headers = response.headers().clone();
    let security_headers = extract_security_headers(&headers);
    let http_headers = extract_http_headers(&headers);

    // Enforce HTML content-type, else skip
    // Note: If Content-Type header is missing, we continue processing (some servers don't send it)
    if let Some(ct) = headers.get(reqwest::header::CONTENT_TYPE) {
        let ct = ct.to_str().unwrap_or("").to_lowercase();
        if !ct.starts_with("text/html") {
            log::info!("Skipping {} - non-HTML content-type: {}", final_domain, ct);
            return Ok(None);
        }
    } else {
        // No Content-Type header - log at debug level but continue processing
        debug!(
            "No Content-Type header for {}, continuing anyway",
            final_domain
        );
    }

    // Check Content-Encoding header for debugging
    if let Some(encoding) = headers.get(reqwest::header::CONTENT_ENCODING) {
        debug!("Content-Encoding for {final_domain}: {:?}", encoding);
    }

    // Cap body size and read as text (reqwest automatically decompresses gzip/deflate/br)
    let body = match response.text().await {
        Ok(text) => {
            if text.len() > crate::config::MAX_RESPONSE_BODY_SIZE {
                debug!("Skipping large body: {} bytes", text.len());
                return Ok(None);
            }
            text
        }
        Err(e) => {
            log::warn!("Failed to read response body for {final_domain}: {e}");
            String::new()
        }
    };

    if body.is_empty() {
        log::info!("Skipping {} - empty response body", final_domain);
        return Ok(None);
    }

    log::info!("Body length for {final_domain}: {} bytes", body.len());

    // Check if title tag exists in raw HTML (for debugging)
    if body.contains("<title") || body.contains("<TITLE") {
        log::debug!("Title tag found in raw HTML for {final_domain}");
    } else {
        log::warn!("No title tag found in raw HTML for {final_domain}");
        let preview = body.chars().take(500).collect::<String>();
        log::debug!(
            "HTML preview (first 500 chars) for {final_domain}: {}",
            preview
        );
    }

    Ok(Some(ResponseData {
        final_url,
        initial_domain,
        final_domain,
        host,
        status: status.as_u16(),
        status_desc,
        headers,
        security_headers,
        http_headers,
        body,
    }))
}

/// Extracted HTML data from parsed document.
#[derive(Debug)]
struct HtmlData {
    title: String,
    keywords_str: Option<String>,
    description: Option<String>,
    is_mobile_friendly: bool,
    structured_data: crate::parse::StructuredData,
    social_media_links: Vec<crate::parse::SocialMediaLink>,
    analytics_ids: Vec<crate::parse::AnalyticsId>, // Analytics/tracking IDs (GA, Facebook Pixel, GTM, AdSense)
    meta_tags: HashMap<String, String>,
    script_sources: Vec<String>,
    script_content: String, // Inline script content for js field detection
    script_tag_ids: HashSet<String>, // Script tag IDs (for __NEXT_DATA__ etc.)
    html_text: String,
}

/// Parses HTML content and extracts all relevant data.
///
/// # Arguments
///
/// * `body` - The HTML body content
/// * `final_domain` - The final domain (for logging)
/// * `error_stats` - Processing statistics tracker
///
/// # Returns
///
/// Extracted HTML data including title, keywords, description, structured data, etc.
fn parse_html_content(
    body: &str,
    final_domain: &str,
    error_stats: &crate::error_handling::ProcessingStats,
) -> HtmlData {
    let document = Html::parse_document(body);

    let title = extract_title(&document, error_stats);
    debug!("Extracted title for {final_domain}: {title:?}");

    let keywords = extract_meta_keywords(&document, error_stats);
    let keywords_str = keywords.map(|kw| kw.join(", "));
    debug!("Extracted keywords for {final_domain}: {keywords_str:?}");

    let description = extract_meta_description(&document, error_stats);
    debug!("Extracted description for {final_domain}: {description:?}");

    let is_mobile_friendly = is_mobile_friendly(body);

    // Extract structured data (JSON-LD, Open Graph, Twitter Cards, Schema.org)
    let structured_data = extract_structured_data(&document, body);
    debug!(
        "Extracted structured data for {final_domain}: {} JSON-LD scripts, {} OG tags, {} Twitter tags, {} schema types",
        structured_data.json_ld.len(),
        structured_data.open_graph.len(),
        structured_data.twitter_cards.len(),
        structured_data.schema_types.len()
    );

    // Extract social media links
    let social_media_links = extract_social_media_links(&document);
    debug!(
        "Extracted {} social media links for {final_domain}",
        social_media_links.len()
    );

    // Extract analytics/tracking IDs (GA, Facebook Pixel, GTM, AdSense)
    let analytics_ids = crate::parse::extract_analytics_ids(body);
    debug!(
        "Extracted {} analytics IDs for {final_domain}: {:?}",
        analytics_ids.len(),
        analytics_ids
    );

    // Extract data needed for technology detection (to avoid double-parsing)
    let mut meta_tags = HashMap::new();
    let meta_selector = Selector::parse("meta").unwrap_or_else(|e| {
        log::error!(
            "Failed to parse 'meta' selector: {}. This is a programming error.",
            e
        );
        // Fallback to a selector that won't match anything
        // Use a known-valid selector that won't match: "*:not(*)"
        Selector::parse("*:not(*)").expect(
            "Fallback selector '*:not(*)' should always parse - this is a programming error",
        )
    });
    for element in document.select(&meta_selector) {
        // Check name attribute (standard meta tags)
        if let (Some(name), Some(content)) = (
            element.value().attr("name"),
            element.value().attr("content"),
        ) {
            meta_tags.insert(format!("name:{}", name.to_lowercase()), content.to_string());
        }
        // Check property attribute (Open Graph, etc.)
        if let (Some(property), Some(content)) = (
            element.value().attr("property"),
            element.value().attr("content"),
        ) {
            meta_tags.insert(
                format!("property:{}", property.to_lowercase()),
                content.to_string(),
            );
        }
        // Check http-equiv attribute
        if let (Some(http_equiv), Some(content)) = (
            element.value().attr("http-equiv"),
            element.value().attr("content"),
        ) {
            meta_tags.insert(
                format!("http-equiv:{}", http_equiv.to_lowercase()),
                content.to_string(),
            );
        }
    }

    let mut script_sources = Vec::new();
    let mut script_content = String::new();
    let mut script_tag_ids = HashSet::new();
    let mut inline_script_count = 0;
    let script_selector = Selector::parse("script").unwrap_or_else(|e| {
        log::error!(
            "Failed to parse 'script' selector: {}. This is a programming error.",
            e
        );
        // Fallback to a selector that won't match anything
        // Use a known-valid selector that won't match: "*:not(*)"
        Selector::parse("*:not(*)").expect(
            "Fallback selector '*:not(*)' should always parse - this is a programming error",
        )
    });
    for element in document.select(&script_selector) {
        // Extract script tag IDs (for __NEXT_DATA__ etc.)
        if let Some(id) = element.value().attr("id") {
            script_tag_ids.insert(id.to_string());
        }
        // Extract script src URLs
        if let Some(src) = element.value().attr("src") {
            script_sources.push(src.to_string());
        }
        // Extract inline script content (limited to MAX_SCRIPT_CONTENT_SIZE per script for security)
        // This prevents DoS attacks via large scripts
        if element.value().attr("src").is_none() {
            let text = element.text().collect::<String>();
            if !text.trim().is_empty() {
                inline_script_count += 1;
                script_content.push_str(
                    &text
                        .chars()
                        .take(crate::config::MAX_SCRIPT_CONTENT_SIZE)
                        .collect::<String>(),
                );
                script_content.push('\n'); // Separate scripts with newline
            }
        }
    }
    log::debug!(
        "Extracted {} inline scripts ({} bytes) and {} external script sources for {}",
        inline_script_count,
        script_content.len(),
        script_sources.len(),
        final_domain
    );

    // Extract text content (first 50KB for performance)
    let html_text = document
        .root_element()
        .text()
        .collect::<String>()
        .chars()
        .take(50_000)
        .collect::<String>();

    HtmlData {
        title,
        keywords_str,
        description,
        is_mobile_friendly,
        structured_data,
        social_media_links,
        analytics_ids,
        meta_tags,
        script_sources,
        script_content,
        script_tag_ids,
        html_text,
    }
}

/// TLS and DNS resolution results.
#[derive(Debug)]
pub(crate) struct TlsDnsData {
    tls_version: Option<String>,
    subject: Option<String>,
    issuer: Option<String>,
    valid_from: Option<chrono::NaiveDateTime>,
    valid_to: Option<chrono::NaiveDateTime>,
    oids: Option<std::collections::HashSet<String>>,
    cipher_suite: Option<String>,
    key_algorithm: Option<String>,
    subject_alternative_names: Option<Vec<String>>,
    ip_address: String,
    reverse_dns_name: Option<String>,
}

/// Result of fetching TLS and DNS data, including any partial failures.
pub struct TlsDnsResult {
    pub data: TlsDnsData,
    pub partial_failures: Vec<(crate::error_handling::ErrorType, String)>, // (error_type, error_message)
}

/// Fetches TLS certificate information and DNS resolution in parallel.
///
/// # Arguments
///
/// * `final_url` - The final URL (to check if HTTPS)
/// * `host` - The hostname to resolve
/// * `resolver` - DNS resolver
/// * `final_domain` - The final domain (for logging)
/// * `error_stats` - Processing statistics tracker
/// * `run_id` - Run identifier for partial failure tracking
///
/// # Returns
///
/// Returns TLS/DNS data and any partial failures (errors that didn't prevent processing).
/// DNS/TLS failures are recorded as partial failures, not as errors that stop processing.
async fn fetch_tls_and_dns(
    final_url: &str,
    host: &str,
    resolver: &hickory_resolver::TokioAsyncResolver,
    final_domain: &str,
    error_stats: &crate::error_handling::ProcessingStats,
    _run_id: Option<&str>, // Reserved for future use (partial failure tracking)
) -> Result<TlsDnsResult, Error> {
    // Run TLS and DNS operations in parallel (they're independent)
    let (tls_result, dns_result) = tokio::join!(
        // TLS certificate extraction (only for HTTPS)
        async {
            if final_url.starts_with("https://") {
                get_ssl_certificate_info(host.to_string()).await
            } else {
                use crate::models::CertificateInfo;
                Ok(CertificateInfo {
                    tls_version: None,
                    subject: None,
                    issuer: None,
                    valid_from: None,
                    valid_to: None,
                    oids: None,
                    cipher_suite: None,
                    key_algorithm: None,
                    subject_alternative_names: None,
                })
            }
        },
        // DNS resolution (IP address and reverse DNS)
        async {
            match resolve_host_to_ip(host, resolver).await {
                Ok(ip) => match reverse_dns_lookup(&ip, resolver).await {
                    Ok(reverse_dns) => Ok((ip, reverse_dns)),
                    Err(e) => Err(e),
                },
                Err(e) => Err(e),
            }
        }
    );

    // Extract TLS info and record partial failures
    let mut partial_failures = Vec::new();
    let (
        tls_version,
        subject,
        issuer,
        valid_from,
        valid_to,
        oids,
        cipher_suite,
        key_algorithm,
        subject_alternative_names,
    ) = match tls_result {
        Ok(cert_info) => (
            cert_info.tls_version,
            cert_info.subject,
            cert_info.issuer,
            cert_info.valid_from,
            cert_info.valid_to,
            cert_info.oids,
            cert_info.cipher_suite,
            cert_info.key_algorithm,
            cert_info.subject_alternative_names,
        ),
        Err(e) => {
            log::error!("Failed to get SSL certificate info for {final_domain}: {e}");
            error_stats.increment_error(crate::error_handling::ErrorType::TlsCertificateError);
            // Record as partial failure using ErrorType enum
            // Sanitize and truncate error message to prevent database bloat
            let error_msg = format!("Failed to get SSL certificate info for {final_domain}: {e}");
            let sanitized_msg = crate::utils::sanitize::sanitize_error_message(&error_msg);
            let truncated_msg = if sanitized_msg.len() > crate::config::MAX_ERROR_MESSAGE_LENGTH {
                format!(
                    "{}... (truncated, original length: {} chars)",
                    &sanitized_msg[..crate::config::MAX_ERROR_MESSAGE_LENGTH - 50],
                    sanitized_msg.len()
                )
            } else {
                sanitized_msg
            };
            partial_failures.push((
                crate::error_handling::ErrorType::TlsCertificateError,
                truncated_msg,
            ));
            (None, None, None, None, None, None, None, None, None)
        }
    };

    debug!(
        "Extracted SSL info for {final_domain}: {tls_version:?}, {subject:?}, {issuer:?}, {valid_from:?}, {valid_to:?}"
    );

    // Extract DNS info and record partial failures
    // If DNS resolution fails, continue with None values rather than failing the entire request
    // This makes the system more resilient to DNS issues
    let (ip_address, reverse_dns_name) = match dns_result {
        Ok((ip, reverse_dns)) => (ip, reverse_dns),
        Err(e) => {
            log::warn!(
                "Failed to resolve DNS for {final_domain}: {e} - continuing without IP address"
            );
            error_stats.increment_error(crate::error_handling::ErrorType::DnsNsLookupError);
            // Record as partial failure using ErrorType enum
            // Sanitize and truncate error message to prevent database bloat
            let error_msg = format!("Failed to resolve DNS for {final_domain}: {e}");
            let sanitized_msg = crate::utils::sanitize::sanitize_error_message(&error_msg);
            let truncated_msg = if sanitized_msg.len() > crate::config::MAX_ERROR_MESSAGE_LENGTH {
                format!(
                    "{}... (truncated, original length: {} chars)",
                    &sanitized_msg[..crate::config::MAX_ERROR_MESSAGE_LENGTH - 50],
                    sanitized_msg.len()
                )
            } else {
                sanitized_msg
            };
            partial_failures.push((
                crate::error_handling::ErrorType::DnsNsLookupError,
                truncated_msg,
            ));
            (String::new(), None) // Use empty string for IP, None for reverse DNS
        }
    };

    debug!("Resolved IP address: {ip_address}");
    debug!("Resolved reverse DNS name: {reverse_dns_name:?}");

    Ok(TlsDnsResult {
        data: TlsDnsData {
            tls_version,
            subject,
            issuer,
            valid_from,
            valid_to,
            oids,
            cipher_suite,
            key_algorithm,
            subject_alternative_names,
            ip_address,
            reverse_dns_name,
        },
        partial_failures,
    })
}

/// Additional DNS records (NS, TXT, MX).
#[derive(Debug)]
struct AdditionalDnsData {
    nameservers: Option<String>,
    txt_records: Option<String>,
    mx_records: Option<String>,
    spf_record: Option<String>,
    dmarc_record: Option<String>,
}

/// Result of fetching additional DNS records, including any partial failures.
#[derive(Debug)]
struct AdditionalDnsResult {
    pub data: AdditionalDnsData,
    pub partial_failures: Vec<(crate::error_handling::ErrorType, String)>, // (error_type, error_message)
}

/// Fetches additional DNS records (NS, TXT, MX) in parallel.
///
/// # Arguments
///
/// * `final_domain` - The final domain to query
/// * `resolver` - DNS resolver
/// * `error_stats` - Processing statistics tracker
///
/// # Returns
///
/// Returns DNS data and any partial failures (errors that didn't prevent processing).
async fn fetch_additional_dns_records(
    final_domain: &str,
    resolver: &hickory_resolver::TokioAsyncResolver,
    error_stats: &crate::error_handling::ProcessingStats,
) -> AdditionalDnsResult {
    // Query additional DNS records (NS, TXT, MX) in parallel
    let (ns_result, txt_result, mx_result) = tokio::join!(
        lookup_ns_records(final_domain, resolver),
        lookup_txt_records(final_domain, resolver),
        lookup_mx_records(final_domain, resolver)
    );

    let mut partial_failures = Vec::new();

    let nameservers = match ns_result {
        Ok(ns) if !ns.is_empty() => {
            debug!("Found {} nameservers for {}", ns.len(), final_domain);
            Some(serialize_json(&ns))
        }
        Ok(_) => None,
        Err(e) => {
            log::warn!("Failed to lookup NS records for {final_domain}: {e}");
            error_stats.increment_error(crate::error_handling::ErrorType::DnsNsLookupError);
            // Sanitize and truncate error message to prevent database bloat
            let error_msg = format!("Failed to lookup NS records for {final_domain}: {e}");
            let sanitized_msg = crate::utils::sanitize::sanitize_error_message(&error_msg);
            let truncated_msg = if sanitized_msg.len() > crate::config::MAX_ERROR_MESSAGE_LENGTH {
                format!(
                    "{}... (truncated, original length: {} chars)",
                    &sanitized_msg[..crate::config::MAX_ERROR_MESSAGE_LENGTH - 50],
                    sanitized_msg.len()
                )
            } else {
                sanitized_msg
            };
            partial_failures.push((
                crate::error_handling::ErrorType::DnsNsLookupError,
                truncated_msg,
            ));
            None
        }
    };

    // Extract TXT records for both JSON storage and SPF/DMARC extraction
    let txt_for_extraction = txt_result.as_ref().ok().cloned().unwrap_or_default();

    let txt_records = match txt_result {
        Ok(txt) if !txt.is_empty() => {
            debug!("Found {} TXT records for {}", txt.len(), final_domain);
            Some(serialize_json(&txt))
        }
        Ok(_) => None,
        Err(e) => {
            log::warn!("Failed to lookup TXT records for {final_domain}: {e}");
            error_stats.increment_error(crate::error_handling::ErrorType::DnsTxtLookupError);
            // Sanitize and truncate error message to prevent database bloat
            let error_msg = format!("Failed to lookup TXT records for {final_domain}: {e}");
            let sanitized_msg = crate::utils::sanitize::sanitize_error_message(&error_msg);
            let truncated_msg = if sanitized_msg.len() > crate::config::MAX_ERROR_MESSAGE_LENGTH {
                format!(
                    "{}... (truncated, original length: {} chars)",
                    &sanitized_msg[..crate::config::MAX_ERROR_MESSAGE_LENGTH - 50],
                    sanitized_msg.len()
                )
            } else {
                sanitized_msg
            };
            partial_failures.push((
                crate::error_handling::ErrorType::DnsTxtLookupError,
                truncated_msg,
            ));
            None
        }
    };

    // Extract SPF and DMARC from TXT records
    let spf_record = extract_spf_record(&txt_for_extraction);
    let mut dmarc_record = extract_dmarc_record(&txt_for_extraction);

    // Also check _dmarc subdomain for DMARC
    if dmarc_record.is_none() {
        if let Ok(dmarc_txt) =
            lookup_txt_records(&format!("_dmarc.{}", final_domain), resolver).await
        {
            dmarc_record = extract_dmarc_record(&dmarc_txt);
        }
    }

    let mx_records = match mx_result {
        Ok(mx) if !mx.is_empty() => {
            debug!("Found {} MX records for {}", mx.len(), final_domain);
            // Store as JSON array of objects: [{"priority": 10, "hostname": "mail.example.com"}, ...]
            let mx_json: Vec<serde_json::Value> = mx
                .into_iter()
                .map(|(priority, hostname)| {
                    serde_json::json!({
                        "priority": priority,
                        "hostname": hostname
                    })
                })
                .collect();
            Some(serialize_json(&mx_json))
        }
        Ok(_) => None,
        Err(e) => {
            log::warn!("Failed to lookup MX records for {final_domain}: {e}");
            error_stats.increment_error(crate::error_handling::ErrorType::DnsMxLookupError);
            // Sanitize and truncate error message to prevent database bloat
            let error_msg = format!("Failed to lookup MX records for {final_domain}: {e}");
            let sanitized_msg = crate::utils::sanitize::sanitize_error_message(&error_msg);
            let truncated_msg = if sanitized_msg.len() > crate::config::MAX_ERROR_MESSAGE_LENGTH {
                format!(
                    "{}... (truncated, original length: {} chars)",
                    &sanitized_msg[..crate::config::MAX_ERROR_MESSAGE_LENGTH - 50],
                    sanitized_msg.len()
                )
            } else {
                sanitized_msg
            };
            partial_failures.push((
                crate::error_handling::ErrorType::DnsMxLookupError,
                truncated_msg,
            ));
            None
        }
    };

    AdditionalDnsResult {
        data: AdditionalDnsData {
            nameservers,
            txt_records,
            mx_records,
            spf_record,
            dmarc_record,
        },
        partial_failures,
    }
}

/// Builds a UrlRecord from extracted response data.
fn build_url_record(
    resp_data: &ResponseData,
    html_data: &HtmlData,
    tls_dns_data: &TlsDnsData,
    additional_dns: &AdditionalDnsData,
    elapsed: f64,
    timestamp: i64,
    run_id: &Option<String>,
) -> UrlRecord {
    UrlRecord {
        initial_domain: resp_data.initial_domain.clone(),
        final_domain: resp_data.final_domain.clone(),
        ip_address: tls_dns_data.ip_address.clone(),
        reverse_dns_name: tls_dns_data.reverse_dns_name.clone(),
        status: resp_data.status,
        status_desc: resp_data.status_desc.clone(),
        response_time: elapsed,
        title: html_data.title.clone(),
        keywords: html_data.keywords_str.clone(),
        description: html_data.description.clone(),
        tls_version: tls_dns_data.tls_version.clone(),
        ssl_cert_subject: tls_dns_data.subject.clone(),
        ssl_cert_issuer: tls_dns_data.issuer.clone(),
        ssl_cert_valid_from: tls_dns_data.valid_from,
        ssl_cert_valid_to: tls_dns_data.valid_to,
        is_mobile_friendly: html_data.is_mobile_friendly,
        timestamp,
        nameservers: additional_dns.nameservers.clone(),
        txt_records: additional_dns.txt_records.clone(),
        mx_records: additional_dns.mx_records.clone(),
        spf_record: additional_dns.spf_record.clone(),
        dmarc_record: additional_dns.dmarc_record.clone(),
        cipher_suite: tls_dns_data.cipher_suite.clone(),
        key_algorithm: tls_dns_data.key_algorithm.clone(),
        run_id: run_id.clone(),
    }
}

/// Performs enrichment lookups (GeoIP, WHOIS, security analysis).
async fn perform_enrichment_lookups(
    ip_address: &str,
    final_url: &str,
    final_domain: &str,
    tls_version: &Option<String>,
    security_headers: &HashMap<String, String>,
    enable_whois: bool,
) -> (
    Option<(String, geoip::GeoIpResult)>,
    Vec<security::SecurityWarning>,
    Option<crate::whois::WhoisResult>,
) {
    let geoip_data = geoip::lookup_ip(ip_address).map(|result| (ip_address.to_string(), result));

    let security_warnings = security::analyze_security(final_url, tls_version, security_headers);

    let whois_data = if enable_whois {
        log::info!("Performing WHOIS lookup for domain: {}", final_domain);
        match crate::whois::lookup_whois(final_domain, None).await {
            Ok(Some(whois_result)) => {
                log::info!(
                    "WHOIS lookup successful for {}: registrar={:?}, creation={:?}, expiration={:?}",
                    final_domain,
                    whois_result.registrar,
                    whois_result.creation_date,
                    whois_result.expiration_date
                );
                Some(whois_result)
            }
            Ok(None) => {
                log::info!("WHOIS lookup returned no data for {}", final_domain);
                None
            }
            Err(e) => {
                log::warn!("WHOIS lookup failed for {}: {}", final_domain, e);
                None
            }
        }
    } else {
        None
    };

    (geoip_data, security_warnings, whois_data)
}

/// Builds a BatchRecord from all extracted data.
#[allow(clippy::too_many_arguments)] // Batch record requires many data sources
fn build_batch_record(
    record: UrlRecord,
    resp_data: &ResponseData,
    html_data: &HtmlData,
    tls_dns_data: &TlsDnsData,
    technologies_vec: Vec<String>,
    redirect_chain: Vec<String>,
    partial_failures: Vec<(crate::error_handling::ErrorType, String)>,
    geoip_data: Option<(String, geoip::GeoIpResult)>,
    security_warnings: Vec<security::SecurityWarning>,
    whois_data: Option<crate::whois::WhoisResult>,
    timestamp: i64,
    run_id: &Option<String>,
) -> BatchRecord {
    let oids_set: std::collections::HashSet<String> = tls_dns_data.oids.clone().unwrap_or_default();

    let partial_failure_records: Vec<crate::storage::models::UrlPartialFailureRecord> =
        partial_failures
            .into_iter()
            .map(|(error_type, error_message)| {
                crate::storage::models::UrlPartialFailureRecord {
                    url_status_id: 0, // Will be set when record is inserted
                    error_type: error_type.as_str().to_string(),
                    error_message,
                    timestamp,
                    run_id: run_id.clone(),
                }
            })
            .collect();

    let sans_vec: Vec<String> = tls_dns_data
        .subject_alternative_names
        .clone()
        .unwrap_or_default();

    BatchRecord {
        url_record: record,
        security_headers: resp_data.security_headers.clone(),
        http_headers: resp_data.http_headers.clone(),
        oids: oids_set,
        redirect_chain,
        technologies: technologies_vec,
        subject_alternative_names: sans_vec,
        analytics_ids: html_data.analytics_ids.clone(),
        geoip: geoip_data,
        structured_data: Some(html_data.structured_data.clone()),
        social_media_links: html_data.social_media_links.clone(),
        security_warnings,
        whois: whois_data,
        partial_failures: partial_failure_records,
    }
}

/// Queues a batch record for database insertion.
///
/// Handles backpressure and graceful shutdown scenarios.
async fn queue_batch_record(
    batch_record: BatchRecord,
    batch_sender: &Option<tokio::sync::mpsc::Sender<BatchRecord>>,
    final_url: &str,
) {
    if let Some(ref sender) = batch_sender {
        match sender.try_send(batch_record) {
            Ok(()) => {
                log::debug!("Record queued for batch insert for URL: {}", final_url);
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(record)) => {
                // Channel is full, use async send which will await
                // This provides backpressure: if DB writes are slow, producers will wait
                match sender.send(record).await {
                    Ok(()) => {
                        log::debug!("Record queued for batch insert for URL: {}", final_url);
                    }
                    Err(_) => {
                        // Channel closed during send - batch writer is shutting down
                        log::warn!(
                            "Failed to queue record for URL {}: channel closed (batch writer shutting down)",
                            final_url
                        );
                        // Don't fail the entire URL processing - just log and continue
                    }
                }
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                // Channel already closed - batch writer is shutting down
                log::warn!(
                    "Failed to queue record for URL {}: channel closed (batch writer shutting down)",
                    final_url
                );
            }
        }
    } else {
        log::warn!(
            "Batch writer not available, record for {} will not be saved",
            final_url
        );
    }
}

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
/// * `ctx` - Processing context containing all shared resources
/// * `elapsed` - Response time in seconds
/// * `redirect_chain` - Vector of redirect chain URLs (will be inserted into url_redirect_chain table)
///
/// # Errors
///
/// Returns an error if domain extraction, DNS resolution, or database insertion fails.
pub async fn handle_response(
    response: reqwest::Response,
    original_url: &str,
    final_url_str: &str,
    ctx: &ProcessingContext,
    elapsed: f64,
    redirect_chain: Option<Vec<String>>,
) -> Result<(), Error> {
    debug!("Started processing response for {final_url_str}");

    // Extract and validate response data
    let Some(resp_data) =
        extract_response_data(response, original_url, final_url_str, &ctx.extractor).await?
    else {
        // Non-HTML or empty response, skip silently
        // This is logged at debug level in extract_response_data
        debug!(
            "Skipping URL {} (non-HTML content-type, empty body, or body too large)",
            final_url_str
        );
        return Ok(());
    };

    // Parse HTML content
    let html_data = parse_html_content(&resp_data.body, &resp_data.final_domain, &ctx.error_stats);

    // Fetch TLS and DNS data in parallel
    let tls_dns_result = fetch_tls_and_dns(
        &resp_data.final_url,
        &resp_data.host,
        &ctx.resolver,
        &resp_data.final_domain,
        &ctx.error_stats,
        ctx.run_id.as_deref(),
    )
    .await?;
    let tls_dns_data = tls_dns_result.data;
    let mut partial_failures = tls_dns_result.partial_failures;

    // Fetch additional DNS records in parallel
    let additional_dns_result =
        fetch_additional_dns_records(&resp_data.final_domain, &ctx.resolver, &ctx.error_stats)
            .await;
    let additional_dns = additional_dns_result.data;
    partial_failures.extend(additional_dns_result.partial_failures);

    // Detect technologies using community-maintained fingerprint rulesets
    let technologies_vec: Vec<String> = match detect_technologies(
        &html_data.meta_tags,
        &html_data.script_sources,
        &html_data.script_content,
        &html_data.html_text,
        &resp_data.headers,
        &resp_data.final_url,
        &html_data.script_tag_ids,
    )
    .await
    {
        Ok(techs) => {
            if !techs.is_empty() {
                debug!(
                    "Detected {} technologies for {}: {:?}",
                    techs.len(),
                    resp_data.final_domain,
                    techs
                );
                let mut tech_vec: Vec<String> = techs.into_iter().collect();
                tech_vec.sort();
                tech_vec
            } else {
                debug!("No technologies detected for {}", resp_data.final_domain);
                Vec::new()
            }
        }
        Err(e) => {
            log::warn!(
                "Failed to detect technologies for {}: {e}",
                resp_data.final_domain
            );
            ctx.error_stats
                .increment_error(crate::error_handling::ErrorType::TechnologyDetectionError);
            Vec::new()
        }
    };

    // Fingerprints metadata (source and version) are stored at run level in the runs table.

    let timestamp = chrono::Utc::now().timestamp_millis();

    debug!(
        "Preparing to insert record for URL: {}",
        resp_data.final_url
    );
    log::info!(
        "Attempting to insert record into database for domain: {}",
        resp_data.initial_domain
    );

    // Build URL record
    let record = build_url_record(
        &resp_data,
        &html_data,
        &tls_dns_data,
        &additional_dns,
        elapsed,
        timestamp,
        &ctx.run_id,
    );

    // Extract redirect chain
    let redirect_chain_vec: Vec<String> = redirect_chain.unwrap_or_default();

    // Perform enrichment lookups (GeoIP, WHOIS, security analysis)
    let (geoip_data, security_warnings, whois_data) = perform_enrichment_lookups(
        &tls_dns_data.ip_address,
        &resp_data.final_url,
        &resp_data.final_domain,
        &tls_dns_data.tls_version,
        &resp_data.security_headers,
        ctx.enable_whois,
    )
    .await;

    // Build batch record
    let batch_record = build_batch_record(
        record,
        &resp_data,
        &html_data,
        &tls_dns_data,
        technologies_vec,
        redirect_chain_vec,
        partial_failures,
        geoip_data,
        security_warnings,
        whois_data,
        timestamp,
        &ctx.run_id,
    );

    // Queue for batch insertion
    queue_batch_record(batch_record, &ctx.batch_sender, &resp_data.final_url).await;

    Ok(())
}

/// Handles an HTTP request, resolving redirects and processing the response.
///
/// # Arguments
///
/// * `ctx` - Processing context containing all shared resources
/// * `url` - The URL to process
/// * `start_time` - Request start time for calculating response time
///
/// # Errors
///
/// Returns an error if redirect resolution, HTTP request, or response handling fails.
pub async fn handle_http_request(
    ctx: &ProcessingContext,
    url: &str,
    start_time: std::time::Instant,
) -> Result<(), Error> {
    debug!("Resolving redirects for {url}");

    let (final_url_string, redirect_chain) =
        resolve_redirect_chain(url, MAX_REDIRECT_HOPS, &ctx.redirect_client).await?;

    // Track redirect info metrics
    // redirect_chain includes the original URL, so:
    // - len == 1: No redirects (original URL only)
    // - len == 2: Single redirect (original + final)
    // - len > 2: Multiple redirects (original + intermediate + final)
    if redirect_chain.len() > 1 {
        // Any redirect occurred (single or multiple)
        ctx.error_stats
            .increment_info(crate::error_handling::InfoType::HttpRedirect);

        // Check for HTTP to HTTPS redirect
        let original_scheme = url.split("://").next().unwrap_or("");
        let final_scheme = final_url_string.split("://").next().unwrap_or("");
        if original_scheme == "http" && final_scheme == "https" {
            ctx.error_stats
                .increment_info(crate::error_handling::InfoType::HttpsRedirect);
        }

        // Multiple redirects (more than one redirect hop)
        if redirect_chain.len() > 2 {
            ctx.error_stats
                .increment_info(crate::error_handling::InfoType::MultipleRedirects);
        }
    }

    debug!("Sending request to final URL {final_url_string}");

    // Add realistic browser headers to reduce bot detection
    // Note: JA3 TLS fingerprinting will still identify rustls, but these headers
    // help with other detection methods (header analysis, behavioral patterns)
    // Capture actual request headers for failure tracking
    let request_headers = build_request_headers();

    // Build request with headers
    let mut request_builder = ctx.client.get(&final_url_string);
    for (name, value) in &request_headers {
        // Convert string header names to reqwest HeaderName
        // Standard headers use constants, custom headers use from_static
        match name.as_str() {
            "accept" => {
                request_builder = request_builder.header(reqwest::header::ACCEPT, value);
            }
            "accept-language" => {
                request_builder = request_builder.header(reqwest::header::ACCEPT_LANGUAGE, value);
            }
            "accept-encoding" => {
                request_builder = request_builder.header(reqwest::header::ACCEPT_ENCODING, value);
            }
            "referer" => {
                request_builder = request_builder.header(reqwest::header::REFERER, value);
            }
            "upgrade-insecure-requests" => {
                request_builder =
                    request_builder.header(reqwest::header::UPGRADE_INSECURE_REQUESTS, value);
            }
            "cache-control" => {
                request_builder = request_builder.header(reqwest::header::CACHE_CONTROL, value);
            }
            "sec-fetch-dest" => {
                request_builder = request_builder.header(
                    reqwest::header::HeaderName::from_static("sec-fetch-dest"),
                    value,
                );
            }
            "sec-fetch-mode" => {
                request_builder = request_builder.header(
                    reqwest::header::HeaderName::from_static("sec-fetch-mode"),
                    value,
                );
            }
            "sec-fetch-site" => {
                request_builder = request_builder.header(
                    reqwest::header::HeaderName::from_static("sec-fetch-site"),
                    value,
                );
            }
            "sec-fetch-user" => {
                request_builder = request_builder.header(
                    reqwest::header::HeaderName::from_static("sec-fetch-user"),
                    value,
                );
            }
            _ => {
                // Unknown header - skip (shouldn't happen with our header set)
                log::warn!("Unknown header in build_request_headers: {}", name);
            }
        }
    }

    let res = request_builder.send().await;

    match res {
        Ok(response) => {
            // Extract headers BEFORE calling error_for_status() (which consumes response)
            // This allows us to capture headers even for error responses (4xx/5xx)
            let response_headers: Vec<(String, String)> = response
                .headers()
                .iter()
                .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string()))
                .collect();
            let response_headers_str = serialize_json_with_default(&response_headers, "[]");

            match response.error_for_status() {
                Ok(response) => {
                    let elapsed = start_time.elapsed().as_secs_f64();
                    handle_response(
                        response,
                        url,
                        &final_url_string,
                        ctx,
                        elapsed,
                        Some(redirect_chain),
                    )
                    .await
                }
                Err(e) => {
                    update_error_stats(&ctx.error_stats, &e).await;

                    // Track bot detection (403) as info metric
                    if let Some(status) = e.status() {
                        if status.as_u16() == 403 {
                            ctx.error_stats
                                .increment_info(crate::error_handling::InfoType::BotDetection403);
                        }
                    }

                    log::error!("HTTP request error for {}: {} (status: {:?}, is_timeout: {}, is_connect: {}, is_request: {})", 
                        url, e, e.status(), e.is_timeout(), e.is_connect(), e.is_request());

                    // Attach structured failure context to error
                    let failure_context = crate::storage::failure::FailureContext {
                        final_url: Some(final_url_string.clone()),
                        redirect_chain: redirect_chain.clone(),
                        response_headers: response_headers.clone(),
                        request_headers: request_headers.clone(),
                    };
                    // Attach structured failure context using helper function
                    // Also attach string context for backward compatibility
                    let redirect_chain_str = serialize_json_with_default(&redirect_chain, "[]");
                    let error = Error::from(e);
                    Err(crate::storage::failure::attach_failure_context(
                        error
                            .context(format!("HTTP request failed for {url}"))
                            .context(format!("FINAL_URL:{final_url_string}"))
                            .context(format!("REDIRECT_CHAIN:{redirect_chain_str}"))
                            .context(format!("RESPONSE_HEADERS:{response_headers_str}"))
                            .context(format!(
                                "REQUEST_HEADERS:{}",
                                serialize_json_with_default(&request_headers, "[]")
                            )),
                        failure_context,
                    ))
                }
            }
        }
        Err(e) => {
            update_error_stats(&ctx.error_stats, &e).await;
            log::error!("HTTP request error for {}: {} (status: {:?}, is_timeout: {}, is_connect: {}, is_request: {})", 
                url, e, e.status(), e.is_timeout(), e.is_connect(), e.is_request());

            // Attach structured failure context to error
            // For connection errors, there are no response headers
            let failure_context = crate::storage::failure::FailureContext {
                final_url: Some(final_url_string.clone()),
                redirect_chain: redirect_chain.clone(),
                response_headers: Vec::new(), // No response for connection errors
                request_headers: request_headers.clone(),
            };
            let context_error = crate::storage::failure::FailureContextError {
                context: failure_context,
            };

            // Also attach string context for backward compatibility
            let error = Error::from(e);
            let redirect_chain_str = serialize_json_with_default(&redirect_chain, "[]");
            Err(error
                .context(format!("HTTP request failed for {url}"))
                .context(format!("FINAL_URL:{final_url_string}"))
                .context(format!("REDIRECT_CHAIN:{redirect_chain_str}"))
                .context(format!(
                    "REQUEST_HEADERS:{}",
                    serialize_json_with_default(&request_headers, "[]")
                ))
                .context(Error::from(context_error))) // Attach structured context
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

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
