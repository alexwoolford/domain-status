//! Error categorization and retry strategy.
//!
//! This module provides functions to categorize errors and configure retry strategies.

use std::time::Duration;
use tokio_retry::strategy::ExponentialBackoff;

use super::stats::ProcessingStats;
use super::types::ErrorType;

/// Creates an exponential backoff retry strategy.
///
/// Returns a retry strategy configured with:
/// - Initial delay: `RETRY_INITIAL_DELAY_MS` milliseconds
/// - Backoff factor: `RETRY_FACTOR` (doubles delay each retry)
/// - Maximum delay: `RETRY_MAX_DELAY_SECS` seconds
/// - Maximum attempts: `RETRY_MAX_ATTEMPTS` (prevents infinite retries)
///
/// # Returns
///
/// A retry strategy iterator ready for use with `tokio_retry::Retry`.
/// The iterator is limited to `RETRY_MAX_ATTEMPTS` attempts to prevent
/// infinite retries and ensure we don't exceed `URL_PROCESSING_TIMEOUT`.
pub fn get_retry_strategy() -> impl Iterator<Item = Duration> {
    ExponentialBackoff::from_millis(crate::config::RETRY_INITIAL_DELAY_MS)
        .factor(crate::config::RETRY_FACTOR) // Double the delay with each retry
        .max_delay(Duration::from_secs(crate::config::RETRY_MAX_DELAY_SECS)) // Maximum delay
        .take(crate::config::RETRY_MAX_ATTEMPTS) // Limit total attempts (initial + retries)
}

/// Categorizes a `reqwest::Error` into an `ErrorType`.
///
/// This is the unified error categorization logic used by both
/// `update_error_stats` and `extract_error_type` to ensure consistency.
///
/// # Arguments
///
/// * `error` - The `reqwest::Error` to categorize
///
/// # Returns
///
/// The appropriate `ErrorType` for the error.
pub fn categorize_reqwest_error(error: &reqwest::Error) -> ErrorType {
    // Check HTTP status codes first
    if let Some(status) = error.status() {
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
            // Other client errors (4xx) - use generic format
            _ if status.is_client_error() => {
                return ErrorType::HttpRequestOtherError;
            }
            // Other server errors (5xx) - use generic format
            _ if status.is_server_error() => {
                return ErrorType::HttpRequestOtherError;
            }
            _ => {
                // Non-standard status codes - fall through to check error type
            }
        }
    }

    // Check reqwest error types
    if error.is_builder() {
        ErrorType::HttpRequestBuilderError
    } else if error.is_redirect() {
        ErrorType::HttpRequestRedirectError
    } else if error.is_status() {
        ErrorType::HttpRequestStatusError
    } else if error.is_timeout() {
        ErrorType::HttpRequestTimeoutError
    } else if error.is_request() {
        ErrorType::HttpRequestRequestError
    } else if error.is_connect() {
        ErrorType::HttpRequestConnectError
    } else if error.is_body() {
        ErrorType::HttpRequestBodyError
    } else if error.is_decode() {
        ErrorType::HttpRequestDecodeError
    } else {
        ErrorType::HttpRequestOtherError
    }
}

/// Updates processing statistics based on a `reqwest::Error`.
///
/// Analyzes the error and increments the appropriate `ErrorType` counter.
/// Handles both HTTP status errors (e.g., 429 Too Many Requests) and network-level
/// errors (timeouts, connection failures, etc.).
///
/// # Arguments
///
/// * `stats` - The processing statistics tracker to update
/// * `error` - The `reqwest::Error` to categorize and record
pub async fn update_error_stats(stats: &ProcessingStats, error: &reqwest::Error) {
    let error_type = categorize_reqwest_error(error);
    stats.increment_error(error_type);
}
