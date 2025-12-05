//! Failure recording operations.
//!
//! This module handles recording URL failures in the database with all
//! associated context and satellite data.

use crate::domain::extract_domain;
use crate::storage::circuit_breaker::DbWriteCircuitBreaker;
use crate::storage::insert::insert_url_failure;
use crate::storage::models::UrlFailureRecord;
use anyhow::{Error, Result};
use publicsuffix::List;
use sqlx::SqlitePool;
use std::sync::Arc;

use super::context::FailureContext;
use super::error::{extract_error_type, extract_http_status};

/// Parameters for recording a URL failure.
///
/// This struct groups all parameters needed to record a failure, reducing
/// function argument count and improving maintainability.
pub struct FailureRecordParams<'a> {
    /// Database connection pool
    pub pool: &'a SqlitePool,
    /// Public Suffix List extractor for domain extraction
    pub extractor: &'a List,
    /// The original URL that failed
    pub url: &'a str,
    /// The error that occurred
    pub error: &'a Error,
    /// Failure context (final_url, redirect_chain, headers)
    pub context: FailureContext,
    /// Number of retry attempts made
    pub retry_count: u32,
    /// Time spent before failure (in seconds)
    pub elapsed_time: f64,
    /// Run identifier (optional)
    pub run_id: Option<&'a str>,
    /// Circuit breaker for database write operations
    pub circuit_breaker: Arc<DbWriteCircuitBreaker>,
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
/// * `params` - Parameters for failure recording
pub async fn record_url_failure(params: FailureRecordParams<'_>) -> Result<(), anyhow::Error> {
    // Check if circuit breaker is open (database writes are blocked)
    if params.circuit_breaker.is_circuit_open().await {
        log::warn!(
            "Database write circuit breaker is open - skipping failure record for {} (circuit will retry after cooldown)",
            params.url
        );
        return Ok(()); // Return Ok to avoid propagating error - we've logged the issue
    }
    // Extract context from error chain if not provided directly
    // This allows us to get context even if it wasn't passed explicitly
    let extracted_context = super::context::extract_failure_context(params.error);

    // Use provided context if fields are populated, otherwise use extracted context
    let final_url = params.context.final_url.or(extracted_context.final_url);
    let redirect_chain = if !params.context.redirect_chain.is_empty() {
        params.context.redirect_chain
    } else {
        extracted_context.redirect_chain
    };

    // Extract domain information
    let domain = extract_domain(params.extractor, params.url).unwrap_or_else(|e| {
        log::debug!(
            "Failed to extract domain from URL {}: {}. Using 'unknown' as fallback.",
            params.url,
            e
        );
        "unknown".to_string()
    });

    let final_domain = final_url
        .as_ref()
        .and_then(|u| extract_domain(params.extractor, u).ok());

    // Extract error information
    let error_type = extract_error_type(params.error);

    // Build error message - enhanced: use root cause with error chain summary for complex errors
    // The root cause is typically the first reqwest error or the first meaningful message
    let error_message = {
        // Try to find reqwest error first (most informative)
        let mut found_reqwest = false;
        let mut reqwest_msg = String::new();
        for cause in params.error.chain() {
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
            let chain_count = params.error.chain().count();
            if chain_count > 3 {
                let chain_summary: Vec<String> = params
                    .error
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
            let chain: Vec<String> = params
                .error
                .chain()
                .map(|cause| cause.to_string())
                .collect();
            if chain.len() > 1 {
                format!(
                    "{} (error chain: {})",
                    chain.first().unwrap_or(&params.error.to_string()),
                    chain[1..].join(" -> ")
                )
            } else {
                params.error.to_string()
            }
        };

        // Sanitize error message (remove control characters)
        // Sanitize and truncate error message to prevent database bloat
        crate::utils::sanitize::sanitize_and_truncate_error_message(&msg)
    };
    let http_status = extract_http_status(params.error);
    let response_headers = if !params.context.response_headers.is_empty() {
        params.context.response_headers
    } else {
        extracted_context.response_headers
    };
    let request_headers = if !params.context.request_headers.is_empty() {
        params.context.request_headers
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
        url: params.url.to_string(),
        final_url: final_url.map(|s| s.to_string()),
        domain,
        final_domain,
        error_type: error_type.as_str().to_string(),
        error_message,
        http_status,
        retry_count: params.retry_count,
        elapsed_time_seconds: Some(params.elapsed_time),
        timestamp: chrono::Utc::now().timestamp_millis(),
        run_id: params.run_id.map(|s| s.to_string()),
        redirect_chain,
        response_headers,
        request_headers,
    };

    // Insert failure record
    match insert_url_failure(params.pool, &failure).await {
        Ok(_) => {
            // Record success to reset circuit breaker
            params.circuit_breaker.record_success().await;
            Ok(())
        }
        Err(e) => {
            // Record failure in circuit breaker
            params.circuit_breaker.record_failure().await;
            Err(anyhow::anyhow!("Failed to insert failure record: {}", e))
        }
    }
}
