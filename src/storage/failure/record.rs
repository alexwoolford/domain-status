//! Failure recording operations.
//!
//! This module handles recording URL failures in the database with all
//! associated context and satellite data.

use anyhow::{Error, Result};
use crate::domain::extract_domain;
use crate::storage::circuit_breaker::DbWriteCircuitBreaker;
use crate::storage::insert::insert_url_failure;
use crate::storage::models::UrlFailureRecord;
use publicsuffix::List;
use sqlx::SqlitePool;
use std::sync::Arc;

use super::context::FailureContext;
use super::error::{extract_error_type, extract_http_status};

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
    let extracted_context = super::context::extract_failure_context(error);

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
            if let Some(reqwest_err) = cause.downcast_ref::<reqwest::Error>() {
                reqwest_msg = reqwest_err.to_string();
                // Try to get underlying source for more detail
                use std::error::Error as StdError;
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
        // Sanitize and truncate error message to prevent database bloat
        crate::utils::sanitize::sanitize_and_truncate_error_message(&msg)
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

