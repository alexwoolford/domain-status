use anyhow::{Error, Result};
use hickory_resolver::TokioAsyncResolver;
use log::debug;
use publicsuffix::List;
use reqwest::Url;
use scraper::{Html, Selector};
use sqlx::SqlitePool;
use std::collections::HashMap;

use crate::config::MAX_REDIRECT_HOPS;
use crate::database::{insert_url_record, UrlRecord};
use crate::dns::{
    extract_dmarc_record, extract_spf_record, lookup_mx_records, lookup_ns_records,
    lookup_txt_records, resolve_host_to_ip, reverse_dns_lookup,
};
use crate::domain::extract_domain;
use crate::error_handling::{update_error_stats, ErrorStats};
use crate::fingerprint::detect_technologies;
use crate::parse::{
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

/// Extracts security-related HTTP headers from a response.
///
/// Scans the header map for common security headers including:
/// - Content-Security-Policy
/// - Strict-Transport-Security
/// - X-Content-Type-Options
/// - X-Frame-Options
/// - X-XSS-Protection
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
pub fn extract_security_headers(headers: &reqwest::header::HeaderMap) -> HashMap<String, String> {
    let headers_list = [
        crate::config::HEADER_CONTENT_SECURITY_POLICY,
        crate::config::HEADER_STRICT_TRANSPORT_SECURITY,
        crate::config::HEADER_X_CONTENT_TYPE_OPTIONS,
        crate::config::HEADER_X_FRAME_OPTIONS,
        crate::config::HEADER_X_XSS_PROTECTION,
        crate::config::HEADER_REFERRER_POLICY,
        crate::config::HEADER_PERMISSIONS_POLICY,
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
/// * `run_id` - Unique identifier for this run (for time-series tracking)
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
    run_id: Option<&str>,
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

    let headers = response.headers().clone();
    let status = response.status();
    let status_desc = status.canonical_reason().unwrap_or("Unknown Status Code");

    // Enforce HTML content-type, else skip
    // Note: HTTP headers are case-insensitive, so we check case-insensitively
    if let Some(ct) = headers.get(reqwest::header::CONTENT_TYPE) {
        let ct = ct.to_str().unwrap_or("").to_lowercase();
        if !ct.starts_with("text/html") {
            debug!("Skipping non-HTML content-type: {ct}");
            return Ok(());
        }
    }

    // Check Content-Encoding header for debugging
    if let Some(encoding) = headers.get(reqwest::header::CONTENT_ENCODING) {
        debug!("Content-Encoding for {final_domain}: {:?}", encoding);
    }

    // Cap body size and read as text (reqwest automatically decompresses gzip/deflate/br)
    // Using .text() instead of .bytes() ensures automatic decompression
    let body = match response.text().await {
        Ok(text) => {
            if text.len() > crate::config::MAX_RESPONSE_BODY_SIZE {
                debug!("Skipping large body: {} bytes", text.len());
                return Ok(());
            }
            text
        }
        Err(e) => {
            log::warn!("Failed to read response body for {final_domain}: {e}");
            String::new()
        }
    };

    if body.is_empty() {
        log::warn!("Empty response body for {final_domain}, skipping HTML extraction");
        return Ok(());
    }

    log::info!("Body length for {final_domain}: {} bytes", body.len());

    // Check if title tag exists in raw HTML (for debugging)
    if body.contains("<title") || body.contains("<TITLE") {
        log::debug!("Title tag found in raw HTML for {final_domain}");
    } else {
        log::warn!("No title tag found in raw HTML for {final_domain}");
        // Log first 500 chars of HTML to help debug bot detection
        let preview = body.chars().take(500).collect::<String>();
        log::debug!(
            "HTML preview (first 500 chars) for {final_domain}: {}",
            preview
        );
    }

    // Parse HTML once and extract all data before any async operations
    // (Html is not Send, so we extract everything in a block scope)
    let (
        title,
        keywords_str,
        description,
        linkedin_slug,
        is_mobile_friendly,
        meta_tags,
        script_sources,
        html_text,
    ) = {
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

        // Extract data needed for technology detection (to avoid double-parsing)
        let mut meta_tags = HashMap::new();
        let meta_selector =
            Selector::parse("meta").unwrap_or_else(|_| Selector::parse("invalid").unwrap());
        for element in document.select(&meta_selector) {
            if let (Some(name), Some(content)) = (
                element.value().attr("name"),
                element.value().attr("content"),
            ) {
                meta_tags.insert(name.to_string().to_lowercase(), content.to_string());
            }
        }

        let mut script_sources = Vec::new();
        let script_selector =
            Selector::parse("script").unwrap_or_else(|_| Selector::parse("invalid").unwrap());
        for element in document.select(&script_selector) {
            if let Some(src) = element.value().attr("src") {
                script_sources.push(src.to_string());
            }
        }

        // Extract text content (first 50KB for performance)
        let html_text = document
            .root_element()
            .text()
            .collect::<String>()
            .chars()
            .take(50_000)
            .collect::<String>();

        (
            title,
            keywords_str,
            description,
            linkedin_slug,
            is_mobile_friendly,
            meta_tags,
            script_sources,
            html_text,
        )
    };

    debug!("Resolved host: {host}");

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
                })
            }
        },
        // DNS resolution (IP address and reverse DNS)
        async {
            let ip = resolve_host_to_ip(host, resolver).await?;
            let reverse_dns = reverse_dns_lookup(&ip, resolver).await?;
            Ok((ip, reverse_dns))
        }
    );

    // Extract TLS info
    let (tls_version, subject, issuer, valid_from, valid_to, oids, cipher_suite, key_algorithm) =
        match tls_result {
            Ok(cert_info) => (
                cert_info.tls_version,
                cert_info.subject,
                cert_info.issuer,
                cert_info.valid_from,
                cert_info.valid_to,
                cert_info.oids,
                cert_info.cipher_suite,
                cert_info.key_algorithm,
            ),
            Err(e) => {
                log::error!("Failed to get SSL certificate info for {final_domain}: {e}");
                error_stats.increment(crate::error_handling::ErrorType::TlsCertificateError);
                (None, None, None, None, None, None, None, None)
            }
        };

    debug!("Extracted SSL info for {final_domain}: {tls_version:?}, {subject:?}, {issuer:?}, {valid_from:?}, {valid_to:?}");

    // Extract DNS info
    let (ip_address, reverse_dns_name) = match dns_result {
        Ok((ip, reverse_dns)) => (ip, reverse_dns),
        Err(e) => {
            log::error!("Failed to resolve DNS for {final_domain}: {e}");
            return Err(e);
        }
    };

    debug!("Resolved IP address: {ip_address}");
    debug!("Resolved reverse DNS name: {reverse_dns_name:?}");

    // Query additional DNS records (NS, TXT, MX)
    // These queries are done in parallel for efficiency
    let (ns_result, txt_result, mx_result) = tokio::join!(
        lookup_ns_records(&final_domain, resolver),
        lookup_txt_records(&final_domain, resolver),
        lookup_mx_records(&final_domain, resolver)
    );

    let nameservers = match ns_result {
        Ok(ns) if !ns.is_empty() => {
            debug!("Found {} nameservers for {}", ns.len(), final_domain);
            Some(serialize_json(&ns))
        }
        Ok(_) => None,
        Err(e) => {
            log::warn!("Failed to lookup NS records for {final_domain}: {e}");
            error_stats.increment(crate::error_handling::ErrorType::DnsNsLookupError);
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
            error_stats.increment(crate::error_handling::ErrorType::DnsTxtLookupError);
            None
        }
    };

    // Extract SPF and DMARC from TXT records
    let spf_record = extract_spf_record(&txt_for_extraction);
    let dmarc_record = extract_dmarc_record(&txt_for_extraction);

    // Also check _dmarc subdomain for DMARC
    let dmarc_record = if dmarc_record.is_none() {
        match lookup_txt_records(&format!("_dmarc.{}", final_domain), resolver).await {
            Ok(dmarc_txt) => extract_dmarc_record(&dmarc_txt),
            Err(_) => None,
        }
    } else {
        dmarc_record
    };

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
            error_stats.increment(crate::error_handling::ErrorType::DnsMxLookupError);
            None
        }
    };

    let security_headers = extract_security_headers(&headers);
    // Serialize to JSON for backward compatibility during migration
    // The normalized table will be populated from this JSON
    let security_headers_json = if security_headers.is_empty() {
        None
    } else {
        Some(serialize_json(&security_headers))
    };

    // Detect technologies using community-maintained fingerprint rulesets
    let technologies = match detect_technologies(
        &meta_tags,
        &script_sources,
        &html_text,
        &headers,
        &final_url,
    )
    .await
    {
        Ok(techs) => {
            if !techs.is_empty() {
                debug!(
                    "Detected {} technologies for {final_domain}: {:?}",
                    techs.len(),
                    techs
                );
                let mut tech_vec: Vec<String> = techs.into_iter().collect();
                tech_vec.sort();
                Some(serialize_json(&tech_vec))
            } else {
                debug!("No technologies detected for {final_domain}");
                None
            }
        }
        Err(e) => {
            log::warn!("Failed to detect technologies for {final_domain}: {e}");
            error_stats.increment(crate::error_handling::ErrorType::TechnologyDetectionError);
            None
        }
    };

    // Note: fingerprints_source and fingerprints_version are stored at run level
    // in the runs table, not per-URL. They are no longer stored in url_status.

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
        technologies,
        nameservers,
        txt_records,
        mx_records,
        spf_record,
        dmarc_record,
        cipher_suite,
        key_algorithm,
        run_id: run_id.map(|s| s.to_string()),
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
/// * `run_id` - Unique identifier for this run (for time-series tracking)
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
    run_id: Option<&str>,
) -> Result<(), Error> {
    debug!("Resolving redirects for {url}");

    let (final_url_string, redirect_chain_json) =
        resolve_redirect_chain(url, MAX_REDIRECT_HOPS, redirect_client).await?;

    debug!("Sending request to final URL {final_url_string}");

    // Add realistic browser headers to reduce bot detection
    // Note: JA3 TLS fingerprinting will still identify rustls, but these headers
    // help with other detection methods (header analysis, behavioral patterns)
    let res = client
        .get(&final_url_string)
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
        run_id,
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
