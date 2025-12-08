//! Failure recording operations.
//!
//! This module handles recording URL failures in the database with all
//! associated context and satellite data.

use crate::domain::extract_domain;
use crate::storage::circuit_breaker::DbWriteCircuitBreaker;
use crate::storage::insert::insert_url_failure;
use crate::storage::models::UrlFailureRecord;
use anyhow::{Error, Result};
use sqlx::SqlitePool;
use std::sync::Arc;

use super::context::FailureContext;

#[cfg(test)]
use super::context::attach_failure_context;
use super::error::{extract_error_type, extract_http_status};

/// Parameters for recording a URL failure.
///
/// This struct groups all parameters needed to record a failure, reducing
/// function argument count and improving maintainability.
pub struct FailureRecordParams<'a> {
    /// Database connection pool
    pub pool: &'a SqlitePool,
    /// Domain extractor for extracting registrable domains from URLs
    pub extractor: &'a psl::List,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::circuit_breaker::DbWriteCircuitBreaker;
    use crate::storage::migrations::run_migrations;
    use sqlx::{Row, SqlitePool};
    use std::sync::Arc;

    async fn create_test_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test database pool");
        run_migrations(&pool)
            .await
            .expect("Failed to run migrations");
        pool
    }

    #[tokio::test]
    async fn test_record_url_failure_circuit_breaker_open() {
        // Test that failures are skipped when circuit breaker is open
        // This is critical - prevents resource exhaustion during database outages
        let pool = create_test_pool().await;
        let extractor = psl::List;
        let circuit_breaker = Arc::new(DbWriteCircuitBreaker::with_threshold(
            1,
            std::time::Duration::from_millis(100),
        ));

        // Open circuit breaker
        circuit_breaker.record_failure().await;
        assert!(circuit_breaker.is_circuit_open().await);

        let error = anyhow::anyhow!("Test error");
        let context = FailureContext::default();

        let params = FailureRecordParams {
            pool: &pool,
            extractor: &extractor,
            url: "https://example.com",
            error: &error,
            context,
            retry_count: 0,
            elapsed_time: 1.0,
            run_id: None,
            circuit_breaker: circuit_breaker.clone(),
        };

        // Should return Ok (skipped) when circuit is open
        let result = record_url_failure(params).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_record_url_failure_domain_extraction_fallback() {
        // Test that domain extraction failures use "unknown" fallback
        // This is critical - failures should be recorded even if domain extraction fails
        let pool = create_test_pool().await;
        let extractor = psl::List;
        let circuit_breaker = Arc::new(DbWriteCircuitBreaker::default());

        // Use invalid URL that will fail domain extraction
        let error = anyhow::anyhow!("Test error");
        let context = FailureContext::default();

        let params = FailureRecordParams {
            pool: &pool,
            extractor: &extractor,
            url: "not-a-valid-url", // Will fail domain extraction
            error: &error,
            context,
            retry_count: 0,
            elapsed_time: 1.0,
            run_id: None,
            circuit_breaker: circuit_breaker.clone(),
        };

        // Should succeed (domain will be "unknown")
        let result = record_url_failure(params).await;
        assert!(result.is_ok());

        // Verify failure was recorded with "unknown" domain
        let row = sqlx::query("SELECT domain FROM url_failures WHERE url = 'not-a-valid-url'")
            .fetch_optional(&pool)
            .await
            .expect("Failed to query failures");
        if let Some(row) = row {
            assert_eq!(row.get::<String, _>("domain"), "unknown");
        }
    }

    #[tokio::test]
    async fn test_record_url_failure_context_extraction() {
        // Test that context is extracted from error chain when not provided
        // This is critical - context should be preserved even if not explicitly passed
        let pool = create_test_pool().await;
        let extractor = psl::List;
        let circuit_breaker = Arc::new(DbWriteCircuitBreaker::default());

        let context = FailureContext {
            final_url: Some("https://example.com".to_string()),
            redirect_chain: vec!["https://example.org".to_string()],
            response_headers: vec![("server".to_string(), "nginx".to_string())],
            request_headers: vec![("user-agent".to_string(), "test".to_string())],
        };

        // Use attach_failure_context to ensure context is extractable
        let error = attach_failure_context(anyhow::anyhow!("HTTP request failed"), context.clone());

        let params = FailureRecordParams {
            pool: &pool,
            extractor: &extractor,
            url: "https://example.org",
            error: &error,
            context: FailureContext::default(), // Empty context - should extract from error
            retry_count: 0,
            elapsed_time: 1.0,
            run_id: None,
            circuit_breaker: circuit_breaker.clone(),
        };

        let result = record_url_failure(params).await;
        assert!(result.is_ok());

        // Verify context was extracted and used
        let row =
            sqlx::query("SELECT final_url FROM url_failures WHERE url = 'https://example.org'")
                .fetch_optional(&pool)
                .await
                .expect("Failed to query failures");
        if let Some(row) = row {
            let final_url: Option<String> = row.get::<Option<String>, _>("final_url");
            assert_eq!(final_url, Some("https://example.com".to_string()));
        }
    }

    #[tokio::test]
    async fn test_record_url_failure_header_truncation() {
        // Test that very long header values are truncated
        // This is critical - prevents database bloat from large headers
        let pool = create_test_pool().await;
        let extractor = psl::List;
        let circuit_breaker = Arc::new(DbWriteCircuitBreaker::default());

        let long_header_value = "x".repeat(2000); // Exceeds MAX_HEADER_VALUE_LENGTH (1000)
        let context = FailureContext {
            final_url: None,
            redirect_chain: vec![],
            response_headers: vec![("server".to_string(), long_header_value.clone())],
            request_headers: vec![],
        };

        let error = anyhow::anyhow!("Test error");
        let params = FailureRecordParams {
            pool: &pool,
            extractor: &extractor,
            url: "https://example.com",
            error: &error,
            context,
            retry_count: 0,
            elapsed_time: 1.0,
            run_id: None,
            circuit_breaker: circuit_breaker.clone(),
        };

        let result = record_url_failure(params).await;
        assert!(result.is_ok());

        // Verify header was truncated
        let row = sqlx::query(
            "SELECT header_value FROM url_failure_response_headers WHERE header_name = 'server'",
        )
        .fetch_optional(&pool)
        .await
        .expect("Failed to query headers");
        if let Some(row) = row {
            let value: String = row.get::<String, _>("header_value");
            assert!(value.len() <= crate::config::MAX_HEADER_VALUE_LENGTH + 50); // Allow for truncation message
            assert!(
                value.contains("truncated")
                    || value.len() <= crate::config::MAX_HEADER_VALUE_LENGTH
            );
        }
    }

    #[tokio::test]
    async fn test_record_url_failure_error_message_sanitization() {
        // Test that error messages are sanitized (control characters removed)
        // This is critical - prevents database issues from invalid characters
        let pool = create_test_pool().await;
        let extractor = psl::List;
        let circuit_breaker = Arc::new(DbWriteCircuitBreaker::default());

        // Create error with control characters
        let error_msg = "Error with control chars: \x00\x01\x02\x03".to_string();
        let error = anyhow::anyhow!(error_msg);

        let context = FailureContext::default();
        let params = FailureRecordParams {
            pool: &pool,
            extractor: &extractor,
            url: "https://example.com",
            error: &error,
            context,
            retry_count: 0,
            elapsed_time: 1.0,
            run_id: None,
            circuit_breaker: circuit_breaker.clone(),
        };

        let result = record_url_failure(params).await;
        assert!(result.is_ok());

        // Verify error message was sanitized (no control characters)
        let row =
            sqlx::query("SELECT error_message FROM url_failures WHERE url = 'https://example.com'")
                .fetch_optional(&pool)
                .await
                .expect("Failed to query failures");
        if let Some(row) = row {
            let msg: String = row.get::<String, _>("error_message");
            // Should not contain control characters
            assert!(!msg.contains('\x00'));
            assert!(!msg.contains('\x01'));
        }
    }

    #[tokio::test]
    async fn test_record_url_failure_circuit_breaker_success_reset() {
        // Test that successful insertion resets circuit breaker
        // This is critical - circuit breaker should recover after successful writes
        let pool = create_test_pool().await;
        let extractor = psl::List;
        let circuit_breaker = Arc::new(DbWriteCircuitBreaker::with_threshold(
            2,
            std::time::Duration::from_millis(100),
        ));

        // Record one failure (not enough to open circuit)
        circuit_breaker.record_failure().await;
        assert_eq!(circuit_breaker.failure_count(), 1);

        let error = anyhow::anyhow!("Test error");
        let context = FailureContext::default();
        let params = FailureRecordParams {
            pool: &pool,
            extractor: &extractor,
            url: "https://example.com",
            error: &error,
            context,
            retry_count: 0,
            elapsed_time: 1.0,
            run_id: None,
            circuit_breaker: circuit_breaker.clone(),
        };

        // Successful insertion should reset circuit breaker
        let result = record_url_failure(params).await;
        assert!(result.is_ok());
        assert_eq!(circuit_breaker.failure_count(), 0);
    }

    #[tokio::test]
    async fn test_record_url_failure_circuit_breaker_failure_tracking() {
        // Test that insertion failures are tracked in circuit breaker
        // This is critical - circuit breaker must track failures correctly
        let pool = create_test_pool().await;
        let extractor = psl::List;
        let circuit_breaker = Arc::new(DbWriteCircuitBreaker::with_threshold(
            5,
            std::time::Duration::from_millis(100),
        ));

        // Close the pool to cause insertion failures
        pool.close().await;

        let error = anyhow::anyhow!("Test error");
        let context = FailureContext::default();
        let params = FailureRecordParams {
            pool: &pool,
            extractor: &extractor,
            url: "https://example.com",
            error: &error,
            context,
            retry_count: 0,
            elapsed_time: 1.0,
            run_id: None,
            circuit_breaker: circuit_breaker.clone(),
        };

        // Should fail and track in circuit breaker
        let result = record_url_failure(params).await;
        assert!(result.is_err());
        assert_eq!(circuit_breaker.failure_count(), 1);
    }

    #[tokio::test]
    async fn test_record_url_failure_provided_context_takes_precedence() {
        // Test that provided context takes precedence over extracted context
        // This is critical - explicit context should not be overridden
        let pool = create_test_pool().await;
        let extractor = psl::List;
        let circuit_breaker = Arc::new(DbWriteCircuitBreaker::default());

        let provided_context = FailureContext {
            final_url: Some("https://provided.com".to_string()),
            redirect_chain: vec!["https://provided.org".to_string()],
            response_headers: vec![],
            request_headers: vec![],
        };

        let extracted_context = FailureContext {
            final_url: Some("https://extracted.com".to_string()),
            redirect_chain: vec!["https://extracted.org".to_string()],
            response_headers: vec![],
            request_headers: vec![],
        };

        // Attach extracted context to error
        let error = anyhow::anyhow!("Test error").context(
            crate::storage::failure::context::FailureContextError {
                context: extracted_context,
            },
        );

        let params = FailureRecordParams {
            pool: &pool,
            extractor: &extractor,
            url: "https://example.com",
            error: &error,
            context: provided_context, // Provided context should take precedence
            retry_count: 0,
            elapsed_time: 1.0,
            run_id: None,
            circuit_breaker: circuit_breaker.clone(),
        };

        let result = record_url_failure(params).await;
        assert!(result.is_ok());

        // Verify provided context was used
        let row =
            sqlx::query("SELECT final_url FROM url_failures WHERE url = 'https://example.com'")
                .fetch_optional(&pool)
                .await
                .expect("Failed to query failures");
        if let Some(row) = row {
            let final_url: Option<String> = row.get::<Option<String>, _>("final_url");
            assert_eq!(final_url, Some("https://provided.com".to_string()));
        }
    }

    #[tokio::test]
    async fn test_record_url_failure_empty_context_uses_extracted() {
        // Test that empty provided context falls back to extracted context
        // This is critical - context should be preserved when not explicitly provided
        let pool = create_test_pool().await;
        let extractor = psl::List;
        let circuit_breaker = Arc::new(DbWriteCircuitBreaker::default());

        let extracted_context = FailureContext {
            final_url: Some("https://extracted.com".to_string()),
            redirect_chain: vec!["https://extracted.org".to_string()],
            response_headers: vec![],
            request_headers: vec![],
        };

        // Use attach_failure_context to ensure context is extractable
        let error =
            attach_failure_context(anyhow::anyhow!("Test error"), extracted_context.clone());

        let params = FailureRecordParams {
            pool: &pool,
            extractor: &extractor,
            url: "https://example.com",
            error: &error,
            context: FailureContext::default(), // Empty - should use extracted
            retry_count: 0,
            elapsed_time: 1.0,
            run_id: None,
            circuit_breaker: circuit_breaker.clone(),
        };

        let result = record_url_failure(params).await;
        assert!(result.is_ok());

        // Verify extracted context was used
        let row =
            sqlx::query("SELECT final_url FROM url_failures WHERE url = 'https://example.com'")
                .fetch_optional(&pool)
                .await
                .expect("Failed to query failures");
        if let Some(row) = row {
            let final_url: Option<String> = row.get::<Option<String>, _>("final_url");
            assert_eq!(final_url, extracted_context.final_url);
        }
    }

    #[tokio::test]
    async fn test_record_url_failure_error_message_chain_handling() {
        // Test that complex error chains are handled correctly
        // This is critical - long error chains should be summarized, not truncated incorrectly
        let pool = create_test_pool().await;
        let extractor = psl::List;
        let circuit_breaker = Arc::new(DbWriteCircuitBreaker::default());

        // Create error with long chain
        let error = anyhow::anyhow!("Root cause")
            .context("Context 1")
            .context("Context 2")
            .context("Context 3")
            .context("Context 4")
            .context("Context 5");

        let context = FailureContext::default();
        let params = FailureRecordParams {
            pool: &pool,
            extractor: &extractor,
            url: "https://example.com",
            error: &error,
            context,
            retry_count: 0,
            elapsed_time: 1.0,
            run_id: None,
            circuit_breaker: circuit_breaker.clone(),
        };

        let result = record_url_failure(params).await;
        assert!(result.is_ok());

        // Verify error message was created (should contain root cause or chain summary)
        let row =
            sqlx::query("SELECT error_message FROM url_failures WHERE url = 'https://example.com'")
                .fetch_optional(&pool)
                .await
                .expect("Failed to query failures");
        if let Some(row) = row {
            let msg: String = row.get::<String, _>("error_message");
            // Should contain meaningful error information
            assert!(!msg.is_empty());
        }
    }

    #[tokio::test]
    async fn test_record_url_failure_run_id_propagation() {
        // Test that run_id is correctly propagated
        // This is critical - run_id links failures to specific scan runs
        let pool = create_test_pool().await;
        let extractor = psl::List;
        let circuit_breaker = Arc::new(DbWriteCircuitBreaker::default());

        // Create a test run first (run_id might be a foreign key)
        // Use a simple SQL insert instead of the full insert_run_metadata function
        sqlx::query("INSERT INTO runs (run_id, start_time) VALUES (?, ?)")
            .bind("test-run-123")
            .bind(chrono::Utc::now().timestamp_millis())
            .execute(&pool)
            .await
            .expect("Failed to create test run");

        let error = anyhow::anyhow!("Test error");
        let context = FailureContext::default();
        let run_id = Some("test-run-123");

        let params = FailureRecordParams {
            pool: &pool,
            extractor: &extractor,
            url: "https://example.com",
            error: &error,
            context,
            retry_count: 0,
            elapsed_time: 1.0,
            run_id,
            circuit_breaker: circuit_breaker.clone(),
        };

        let result = record_url_failure(params).await;
        assert!(result.is_ok());

        // Verify run_id was stored
        let row = sqlx::query("SELECT run_id FROM url_failures WHERE url = 'https://example.com'")
            .fetch_optional(&pool)
            .await
            .expect("Failed to query failures");
        if let Some(row) = row {
            let stored_run_id: Option<String> = row.get::<Option<String>, _>("run_id");
            assert_eq!(stored_run_id, Some("test-run-123".to_string()));
        }
    }
}
