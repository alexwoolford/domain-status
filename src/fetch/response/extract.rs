//! HTTP response extraction utilities.

use anyhow::{Error, Result};
use log::debug;

use crate::domain::extract_domain;
use crate::fetch::request::{extract_http_headers, extract_security_headers};
use super::types::ResponseData;

/// Extracts and validates response data from an HTTP response.
///
/// # Arguments
///
/// * `response` - The HTTP response
/// * `original_url` - The original URL before redirects
/// * `_final_url_str` - The final URL after redirects
/// * `extractor` - Public Suffix List extractor
///
/// # Errors
///
/// Returns an error if domain extraction fails or response body cannot be read.
/// Returns `Ok(None)` if content-type is not HTML or body is empty/large.
pub(crate) async fn extract_response_data(
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

    let parsed_url = reqwest::Url::parse(&final_url)?;
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
        let preview = body
            .chars()
            .take(crate::config::MAX_HTML_PREVIEW_CHARS)
            .collect::<String>();
        log::debug!(
            "HTML preview (first {} chars) for {final_domain}: {}",
            crate::config::MAX_HTML_PREVIEW_CHARS,
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

