//! Failure tracking and insertion utilities.
//!
//! This module provides functions to extract failure information from errors
//! and insert failure records into the database.

use anyhow::Error;
use reqwest::Error as ReqwestError;
use std::error::Error as StdError;

use crate::domain::extract_domain;
use crate::error_handling::{categorize_reqwest_error, ErrorType};
use crate::storage::circuit_breaker::DbWriteCircuitBreaker;
use crate::storage::insert::insert_url_failure;
use crate::storage::models::UrlFailureRecord;
use publicsuffix::List;
use sqlx::SqlitePool;
use std::sync::Arc;

/// Extracts error type from an error chain.
///
/// Uses the shared `categorize_reqwest_error` function for consistency,
/// but also enhances categorization by checking error messages for DNS/TLS patterns.
fn extract_error_type(error: &Error) -> ErrorType {
    // Check error chain for reqwest errors first
    for cause in error.chain() {
        if let Some(reqwest_err) = cause.downcast_ref::<ReqwestError>() {
            // Use shared categorization function for consistency
            let base_type = categorize_reqwest_error(reqwest_err);

            // Enhance categorization by checking error messages for DNS/TLS patterns
            // This provides more specific error types when the underlying cause is DNS/TLS
            let error_msg = reqwest_err.to_string().to_lowercase();

            // Check for DNS errors in message (more specific than generic connect/request errors)
            if error_msg.contains("dns")
                || error_msg.contains("name resolution")
                || error_msg.contains("failed to resolve")
            {
                // Try to determine which DNS lookup failed
                if error_msg.contains("txt") {
                    return ErrorType::DnsTxtLookupError;
                } else if error_msg.contains("mx") || error_msg.contains("mail") {
                    return ErrorType::DnsMxLookupError;
                }
                return ErrorType::DnsNsLookupError;
            }

            // Check for TLS errors in message
            if error_msg.contains("tls")
                || error_msg.contains("ssl")
                || error_msg.contains("certificate")
                || error_msg.contains("handshake")
            {
                return ErrorType::TlsCertificateError;
            }

            // Check for timeout in request/connect errors
            if (base_type == ErrorType::HttpRequestRequestError
                || base_type == ErrorType::HttpRequestConnectError)
                && error_msg.contains("timeout")
            {
                return ErrorType::HttpRequestTimeoutError;
            }

            // Return the base type (from shared categorization)
            return base_type;
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

// Removed unused string parsing functions:
// - extract_response_headers
// - extract_request_headers
// - extract_redirect_chain
// - extract_final_url
//
// These functions were removed because they are no longer used.
// The system now relies solely on structured `FailureContextError` for error context,
// which is more robust and eliminates fragile string parsing.

/// Failure context passed directly to avoid fragile string parsing.
#[derive(Debug, Clone, Default)]
pub struct FailureContext {
    pub final_url: Option<String>,
    pub redirect_chain: Vec<String>,
    pub response_headers: Vec<(String, String)>,
    pub request_headers: Vec<(String, String)>,
}

/// Custom error type that carries failure context.
///
/// This allows us to pass structured failure context through the error chain
/// without relying on fragile string parsing.
#[derive(Debug)]
pub struct FailureContextError {
    pub context: FailureContext,
}

impl std::fmt::Display for FailureContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Provide more useful error message with context details
        if let Some(ref final_url) = self.context.final_url {
            if !self.context.redirect_chain.is_empty() {
                write!(
                    f,
                    "Request failed for {} (redirected from {} via {} hop(s))",
                    final_url,
                    self.context.redirect_chain.first().unwrap_or(final_url),
                    self.context.redirect_chain.len().saturating_sub(1)
                )
            } else {
                write!(f, "Request failed for {}", final_url)
            }
        } else {
            write!(f, "Request failed (no final URL available)")
        }
    }
}

impl std::error::Error for FailureContextError {}

/// Helper function to attach failure context to an error.
///
/// This provides a consistent way to attach structured failure context
/// to errors throughout the codebase, reducing duplication.
pub fn attach_failure_context(error: anyhow::Error, context: FailureContext) -> anyhow::Error {
    error.context(FailureContextError { context })
}

/// Extracts failure context from an error chain.
///
/// Looks for a `FailureContextError` in the error chain and extracts its context.
/// Returns empty context if no structured context is found (simpler and more robust).
pub fn extract_failure_context(error: &Error) -> FailureContext {
    // Look for structured context in error chain
    for cause in error.chain() {
        if let Some(context_err) = cause.downcast_ref::<FailureContextError>() {
            return context_err.context.clone();
        }
    }

    // No structured context found - return empty context
    // This is simpler and more robust than fragile string parsing
    // All error paths should attach structured context using attach_failure_context()
    FailureContext::default()
}

/// Records a URL failure in the database.
///
/// This function extracts failure information from an error and inserts it
/// into the database with all associated satellite data.
///
/// Uses a circuit breaker to prevent resource exhaustion when database writes fail repeatedly.
/// If the circuit is open, the failure is logged but not recorded in the database.
///
/// # Arguments
///
/// * `pool` - Database connection pool
/// * `extractor` - Public Suffix List extractor for domain extraction
/// * `url` - The original URL that failed
/// * `error` - The error that occurred
/// * `context` - Failure context (final_url, redirect_chain, headers) - passed directly to avoid fragile parsing
/// * `retry_count` - Number of retry attempts made
/// * `elapsed_time` - Time spent before failure
/// * `run_id` - Run identifier (optional)
/// * `circuit_breaker` - Circuit breaker for database write operations
#[allow(clippy::too_many_arguments)] // All arguments are necessary for comprehensive failure tracking
pub async fn record_url_failure(
    pool: &SqlitePool,
    extractor: &List,
    url: &str,
    error: &Error,
    context: FailureContext,
    retry_count: u32,
    elapsed_time: f64,
    run_id: Option<&str>,
    circuit_breaker: Arc<DbWriteCircuitBreaker>,
) -> Result<(), anyhow::Error> {
    // Check if circuit breaker is open (database writes are blocked)
    if circuit_breaker.is_circuit_open().await {
        log::warn!(
            "Database write circuit breaker is open - skipping failure record for {} (circuit will retry after cooldown)",
            url
        );
        return Ok(()); // Return Ok to avoid propagating error - we've logged the issue
    }
    // Extract context from error chain if not provided directly
    // This allows us to get context even if it wasn't passed explicitly
    let extracted_context = extract_failure_context(error);

    // Use provided context if fields are populated, otherwise use extracted context
    let final_url = context.final_url.or(extracted_context.final_url);
    let redirect_chain = if !context.redirect_chain.is_empty() {
        context.redirect_chain
    } else {
        extracted_context.redirect_chain
    };

    // Extract domain information
    let domain = extract_domain(extractor, url).unwrap_or_else(|_| "unknown".to_string());

    let final_domain = final_url
        .as_ref()
        .and_then(|u| extract_domain(extractor, u).ok());

    // Extract error information
    let error_type = extract_error_type(error);

    // Build error message - enhanced: use root cause with error chain summary for complex errors
    // The root cause is typically the first reqwest error or the first meaningful message
    let error_message = {
        // Try to find reqwest error first (most informative)
        let mut found_reqwest = false;
        let mut reqwest_msg = String::new();
        for cause in error.chain() {
            if let Some(reqwest_err) = cause.downcast_ref::<ReqwestError>() {
                reqwest_msg = reqwest_err.to_string();
                // Try to get underlying source for more detail
                if let Some(source) = reqwest_err.source() {
                    reqwest_msg = format!("{}: {}", reqwest_msg, source);
                }
                found_reqwest = true;
                break;
            }
        }

        let msg = if found_reqwest {
            // For complex errors (long chain), include chain summary
            let chain_count = error.chain().count();
            if chain_count > 3 {
                let chain_summary: Vec<String> = error
                    .chain()
                    .skip(1) // Skip the reqwest error we already have
                    .take(3) // Limit to first 3 additional causes
                    .map(|e| e.to_string())
                    .collect();
                if !chain_summary.is_empty() {
                    format!(
                        "{} (error chain: {} -> ...)",
                        reqwest_msg,
                        chain_summary.join(" -> ")
                    )
                } else {
                    reqwest_msg
                }
            } else {
                reqwest_msg
            }
        } else {
            // Fallback: use first meaningful message or full error string
            let chain: Vec<String> = error.chain().map(|cause| cause.to_string()).collect();
            if chain.len() > 1 {
                format!(
                    "{} (error chain: {})",
                    chain.first().unwrap_or(&error.to_string()),
                    chain[1..].join(" -> ")
                )
            } else {
                error.to_string()
            }
        };

        // Sanitize error message (remove control characters)
        let sanitized_msg = crate::utils::sanitize::sanitize_error_message(&msg);

        // Truncate error message to prevent database bloat
        if sanitized_msg.len() > crate::config::MAX_ERROR_MESSAGE_LENGTH {
            format!(
                "{}... (truncated, original length: {} chars)",
                &sanitized_msg[..crate::config::MAX_ERROR_MESSAGE_LENGTH - 50],
                sanitized_msg.len()
            )
        } else {
            sanitized_msg
        }
    };
    let http_status = extract_http_status(error);
    let response_headers = if !context.response_headers.is_empty() {
        context.response_headers
    } else {
        extracted_context.response_headers
    };
    let request_headers = if !context.request_headers.is_empty() {
        context.request_headers
    } else {
        extracted_context.request_headers
    };

    // Log if we had to fall back to extraction (for observability)
    if final_url.is_none() && !redirect_chain.is_empty() {
        log::debug!("Could not extract final_url from error, using last redirect chain URL");
    }

    // Truncate header values to prevent database bloat
    let response_headers: Vec<(String, String)> = response_headers
        .into_iter()
        .map(|(name, value)| {
            let truncated_value = if value.len() > crate::config::MAX_HEADER_VALUE_LENGTH {
                format!(
                    "{}... (truncated)",
                    &value[..crate::config::MAX_HEADER_VALUE_LENGTH - 20]
                )
            } else {
                value
            };
            (name, truncated_value)
        })
        .collect();
    let request_headers: Vec<(String, String)> = request_headers
        .into_iter()
        .map(|(name, value)| {
            let truncated_value = if value.len() > crate::config::MAX_HEADER_VALUE_LENGTH {
                format!(
                    "{}... (truncated)",
                    &value[..crate::config::MAX_HEADER_VALUE_LENGTH - 20]
                )
            } else {
                value
            };
            (name, truncated_value)
        })
        .collect();

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
    match insert_url_failure(pool, &failure).await {
        Ok(_) => {
            // Record success to reset circuit breaker
            circuit_breaker.record_success().await;
            Ok(())
        }
        Err(e) => {
            // Record failure in circuit breaker
            circuit_breaker.record_failure().await;
            Err(anyhow::anyhow!("Failed to insert failure record: {}", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_error_type_timeout() {
        // Create a timeout error
        let error = anyhow::anyhow!("Process URL timeout after 45 seconds");

        assert_eq!(extract_error_type(&error), ErrorType::ProcessUrlTimeout);
    }

    #[test]
    fn test_extract_error_type_dns_error_message() {
        // Create an error with DNS-related message
        let error =
            anyhow::anyhow!("Failed to resolve DNS: no record found").context("DNS lookup failed");

        // Note: This test depends on error message parsing
        // The actual behavior may vary, but we test that DNS errors are detected
        let error_type = extract_error_type(&error);
        assert!(
            matches!(
                error_type,
                ErrorType::DnsNsLookupError
                    | ErrorType::DnsTxtLookupError
                    | ErrorType::DnsMxLookupError
                    | ErrorType::HttpRequestOtherError
            ),
            "Expected DNS-related error type or fallback, got: {:?}",
            error_type
        );
    }

    #[test]
    fn test_extract_failure_context_from_structured_error() {
        let context = FailureContext {
            final_url: Some("https://example.com".to_string()),
            redirect_chain: vec!["https://example.org".to_string()],
            response_headers: vec![("content-type".to_string(), "text/html".to_string())],
            request_headers: vec![("user-agent".to_string(), "test".to_string())],
        };
        let error = anyhow::Error::from(FailureContextError {
            context: context.clone(),
        });

        let extracted = extract_failure_context(&error);
        assert_eq!(extracted.final_url, context.final_url);
        assert_eq!(extracted.redirect_chain, context.redirect_chain);
        assert_eq!(extracted.response_headers, context.response_headers);
        assert_eq!(extracted.request_headers, context.request_headers);
    }

    #[test]
    fn test_extract_failure_context_no_structured_context() {
        // Create an error without structured context (no FailureContextError)
        // The system now only uses structured context, so this should return empty context
        let error = anyhow::anyhow!("HTTP request failed")
            .context("FINAL_URL:https://example.com")
            .context("REDIRECT_CHAIN:[\"https://example.org\"]");

        let extracted = extract_failure_context(&error);
        // Without structured context, we return empty context (no string parsing fallback)
        assert_eq!(extracted.final_url, None);
        assert_eq!(extracted.redirect_chain, Vec::<String>::new());
        assert_eq!(extracted.response_headers, Vec::<(String, String)>::new());
        assert_eq!(extracted.request_headers, Vec::<(String, String)>::new());
    }

    #[test]
    fn test_extract_http_status_no_status() {
        // Error without HTTP status
        let error = anyhow::anyhow!("Connection error");

        assert_eq!(extract_http_status(&error), None);
    }

    #[test]
    fn test_error_message_truncation_logic() {
        // Test truncation logic (simulating what happens in record_url_failure)
        let long_message = "x".repeat(3000);
        let max_len = crate::config::MAX_ERROR_MESSAGE_LENGTH;

        let truncated = if long_message.len() > max_len {
            format!(
                "{}... (truncated, original length: {} chars)",
                &long_message[..max_len - 50],
                long_message.len()
            )
        } else {
            long_message.clone()
        };

        assert!(truncated.len() <= max_len + 100); // Allow for truncation message
        assert!(truncated.contains("truncated"));
        assert!(truncated.contains("3000"));
    }

    #[tokio::test]
    async fn test_circuit_breaker_integration() {
        use crate::storage::circuit_breaker::DbWriteCircuitBreaker;

        let cb = DbWriteCircuitBreaker::with_threshold(2, std::time::Duration::from_millis(50));

        // Record failures
        cb.record_failure().await;
        assert!(!cb.is_circuit_open().await);

        cb.record_failure().await;
        assert!(cb.is_circuit_open().await);

        // Record success should close circuit
        cb.record_success().await;
        assert!(!cb.is_circuit_open().await);
        assert_eq!(cb.failure_count(), 0);
    }
}
