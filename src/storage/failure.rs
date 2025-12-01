//! Failure tracking and insertion utilities.
//!
//! This module provides functions to extract failure information from errors
//! and insert failure records into the database.

use anyhow::Error;
use reqwest::Error as ReqwestError;
use serde_json;

use crate::domain::extract_domain;
use crate::error_handling::ErrorType;
use crate::storage::insert::insert_url_failure;
use crate::storage::models::UrlFailureRecord;
use publicsuffix::List;
use sqlx::SqlitePool;

/// Extracts error type from an error chain.
fn extract_error_type(error: &Error) -> ErrorType {
    // Check error chain for reqwest errors first
    for cause in error.chain() {
        if let Some(reqwest_err) = cause.downcast_ref::<ReqwestError>() {
            if let Some(status) = reqwest_err.status() {
                // Map specific HTTP status codes to specific error types
                match status.as_u16() {
                    // Client errors (4xx)
                    400 => return ErrorType::HttpRequestBadRequest,
                    401 => return ErrorType::HttpRequestUnauthorized,
                    403 => return ErrorType::HttpRequestBotDetectionError,
                    404 => return ErrorType::HttpRequestNotFound,
                    406 => return ErrorType::HttpRequestNotAcceptable,
                    429 => return ErrorType::HttpRequestTooManyRequests,
                    // Server errors (5xx)
                    500 => return ErrorType::HttpRequestInternalServerError,
                    502 => return ErrorType::HttpRequestBadGateway,
                    503 => return ErrorType::HttpRequestServiceUnavailable,
                    504 => return ErrorType::HttpRequestGatewayTimeout,
                    521 => return ErrorType::HttpRequestCloudflareError,
                    // Other client errors (4xx)
                    _ if status.is_client_error() => return ErrorType::HttpRequestOtherError,
                    // Other server errors (5xx)
                    _ if status.is_server_error() => return ErrorType::HttpRequestOtherError,
                    _ => {
                        // Non-standard status codes - fall through to check reqwest error type
                    }
                }
            }

            // Check reqwest error types
            if reqwest_err.is_builder() {
                return ErrorType::HttpRequestBuilderError;
            } else if reqwest_err.is_redirect() {
                return ErrorType::HttpRequestRedirectError;
            } else if reqwest_err.is_status() {
                return ErrorType::HttpRequestStatusError;
            } else if reqwest_err.is_timeout() {
                return ErrorType::HttpRequestTimeoutError;
            } else if reqwest_err.is_request() {
                return ErrorType::HttpRequestRequestError;
            } else if reqwest_err.is_connect() {
                return ErrorType::HttpRequestConnectError;
            } else if reqwest_err.is_body() {
                return ErrorType::HttpRequestBodyError;
            } else if reqwest_err.is_decode() {
                return ErrorType::HttpRequestDecodeError;
            }
        }
    }

    // Check error message for specific patterns (for errors without reqwest::Error)
    let msg = error.to_string().to_lowercase();
    if msg.contains("timeout") {
        return ErrorType::ProcessUrlTimeout;
    }

    // Check for DNS errors in error message
    if msg.contains("dns") || msg.contains("resolve") || msg.contains("lookup failed") {
        // Try to determine which DNS lookup failed
        if msg.contains("ns") || msg.contains("nameserver") {
            return ErrorType::DnsNsLookupError;
        } else if msg.contains("txt") {
            return ErrorType::DnsTxtLookupError;
        } else if msg.contains("mx") || msg.contains("mail") {
            return ErrorType::DnsMxLookupError;
        }
        // Generic DNS error - default to NS lookup error
        return ErrorType::DnsNsLookupError;
    }

    // Check for TLS errors in error message
    if msg.contains("tls")
        || msg.contains("ssl")
        || msg.contains("certificate")
        || msg.contains("handshake")
    {
        return ErrorType::TlsCertificateError;
    }

    // Default to other error
    ErrorType::HttpRequestOtherError
}

/// Extracts HTTP status code from an error chain.
fn extract_http_status(error: &Error) -> Option<u16> {
    for cause in error.chain() {
        if let Some(reqwest_err) = cause.downcast_ref::<ReqwestError>() {
            if let Some(status) = reqwest_err.status() {
                return Some(status.as_u16());
            }
        }
    }
    None
}

/// Extracts response headers from error context.
///
/// Response headers are captured when we receive an HTTP response with an error status (4xx/5xx).
/// For connection errors, timeouts, etc., there is no response, so headers will be empty.
fn extract_response_headers(error: &Error) -> Vec<(String, String)> {
    for cause in error.chain() {
        let msg = cause.to_string();
        // Look for RESPONSE_HEADERS: prefix (may be at start or embedded)
        if let Some(headers_pos) = msg.find("RESPONSE_HEADERS:") {
            let headers_str = &msg[headers_pos + "RESPONSE_HEADERS:".len()..];
            // Try to find JSON array - look for opening bracket
            if let Some(bracket_start) = headers_str.find('[') {
                let headers_str = &headers_str[bracket_start..];
                // Find matching closing bracket
                let mut bracket_count = 0;
                let mut end_pos = None;
                for (i, ch) in headers_str.char_indices() {
                    match ch {
                        '[' => bracket_count += 1,
                        ']' => {
                            bracket_count -= 1;
                            if bracket_count == 0 {
                                end_pos = Some(i + 1);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(end) = end_pos {
                    if let Ok(headers) =
                        serde_json::from_str::<Vec<(String, String)>>(&headers_str[..end])
                    {
                        return headers;
                    }
                }
            }
        }
    }
    // No response headers found - this is expected for connection errors, timeouts, etc.
    Vec::new()
}

/// Builds request headers that were sent (for debugging bot detection).
fn build_request_headers() -> Vec<(String, String)> {
    // These are the headers we always send - match what's in handle_http_request
    vec![
        ("accept".to_string(), "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".to_string()),
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

/// Extracts redirect chain from error context.
fn extract_redirect_chain(error: &Error) -> Vec<String> {
    for cause in error.chain() {
        let msg = cause.to_string();
        // Look for REDIRECT_CHAIN: prefix (may be at start or embedded)
        if let Some(chain_str) = msg.find("REDIRECT_CHAIN:") {
            let chain_str = &msg[chain_str + "REDIRECT_CHAIN:".len()..];
            // Try to find JSON array - look for opening bracket
            if let Some(bracket_start) = chain_str.find('[') {
                let chain_str = &chain_str[bracket_start..];
                // Find matching closing bracket
                let mut bracket_count = 0;
                let mut end_pos = None;
                for (i, ch) in chain_str.char_indices() {
                    match ch {
                        '[' => bracket_count += 1,
                        ']' => {
                            bracket_count -= 1;
                            if bracket_count == 0 {
                                end_pos = Some(i + 1);
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(end) = end_pos {
                    if let Ok(chain) = serde_json::from_str::<Vec<String>>(&chain_str[..end]) {
                        return chain;
                    }
                }
            }
        }
    }
    Vec::new()
}

/// Extracts final URL from error context.
fn extract_final_url(error: &Error) -> Option<String> {
    for cause in error.chain() {
        let msg = cause.to_string();
        // Look for FINAL_URL: prefix (may be at start or embedded)
        if let Some(url_pos) = msg.find("FINAL_URL:") {
            let url_str = &msg[url_pos + "FINAL_URL:".len()..];
            // Extract URL - it may be followed by whitespace, newline, or another context
            // Stop at whitespace, newline, or REDIRECT_CHAIN marker
            let url = url_str
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim()
                .split('\n')
                .next()
                .unwrap_or("")
                .trim();
            // Also check if it contains REDIRECT_CHAIN and stop there
            let url = if let Some(chain_pos) = url.find("REDIRECT_CHAIN") {
                &url[..chain_pos]
            } else {
                url
            };
            let url = url.trim();
            if !url.is_empty() && url.starts_with("http") {
                return Some(url.to_string());
            }
        }
    }
    // Fallback: if we have a redirect chain, use the last URL as final_url
    let redirect_chain = extract_redirect_chain(error);
    if !redirect_chain.is_empty() {
        return Some(redirect_chain.last().unwrap().clone());
    }
    None
}

/// Records a URL failure in the database.
///
/// This function extracts failure information from an error and inserts it
/// into the database with all associated satellite data.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `extractor` - Public Suffix List extractor for domain extraction
/// * `url` - The original URL that failed
/// * `error` - The error that occurred (contains final_url and redirect_chain in context)
/// * `retry_count` - Number of retry attempts made
/// * `elapsed_time` - Time spent before failure
/// * `run_id` - Run identifier (optional)
pub async fn record_url_failure(
    pool: &SqlitePool,
    extractor: &List,
    url: &str,
    error: &Error,
    retry_count: u32,
    elapsed_time: f64,
    run_id: Option<&str>,
) -> Result<(), anyhow::Error> {
    // Extract failure context from error
    let final_url = extract_final_url(error);
    let redirect_chain = extract_redirect_chain(error);

    // Extract domain information
    let domain = extract_domain(extractor, url).unwrap_or_else(|_| "unknown".to_string());

    let final_domain = final_url
        .as_ref()
        .and_then(|u| extract_domain(extractor, u).ok());

    // Extract error information
    let error_type = extract_error_type(error);
    let error_message = error.to_string();
    let http_status = extract_http_status(error);
    let response_headers = extract_response_headers(error);
    let request_headers = build_request_headers();

    // Build failure record
    let failure = UrlFailureRecord {
        url: url.to_string(),
        final_url: final_url.map(|s| s.to_string()),
        domain,
        final_domain,
        error_type: error_type.as_str().to_string(),
        error_message,
        http_status,
        retry_count,
        elapsed_time_seconds: Some(elapsed_time),
        timestamp: chrono::Utc::now().timestamp_millis(),
        run_id: run_id.map(|s| s.to_string()),
        redirect_chain,
        response_headers,
        request_headers,
    };

    // Insert failure record
    insert_url_failure(pool, &failure)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to insert failure record: {}", e))?;

    Ok(())
}
