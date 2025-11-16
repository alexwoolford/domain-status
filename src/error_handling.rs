use log::SetLoggerError;
use reqwest::Error as ReqwestError;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use strum::IntoEnumIterator;
use strum_macros::EnumIter as EnumIterMacro;
use thiserror::Error;
use tokio_retry::strategy::ExponentialBackoff;

/// Error types for initialization failures.
#[derive(Error, Debug)]
#[allow(clippy::enum_variant_names)] // All variants end with "Error" by convention
pub enum InitializationError {
    /// Error initializing the logger.
    #[error("Logger initialization error: {0}")]
    LoggerError(#[from] SetLoggerError),

    /// Error initializing the HTTP client.
    #[error("HTTP client initialization error: {0}")]
    HttpClientError(#[from] ReqwestError),

    /// Error initializing the DNS resolver.
    #[error("DNS resolver initialization error: {0}")]
    #[allow(dead_code)] // Reserved for future use if fallback fails
    DnsResolverError(String),
}

/// Error types for database operations.
#[derive(Error, Debug)]
pub enum DatabaseError {
    /// Error creating the database file.
    #[error("Database file creation error: {0}")]
    FileCreationError(String),

    /// SQL execution error.
    #[error("SQL error: {0}")]
    SqlError(#[from] sqlx::Error),
}

/// Types of errors that can occur during URL processing.
///
/// This enum categorizes different error conditions for tracking and reporting purposes.
/// Each variant represents a specific failure mode in the URL checking pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIterMacro)]
pub enum ErrorType {
    HttpRequestBuilderError,
    HttpRequestRedirectError,
    HttpRequestStatusError,
    HttpRequestTimeoutError,
    HttpRequestRequestError,
    HttpRequestConnectError,
    HttpRequestBodyError,
    HttpRequestDecodeError,
    HttpRequestOtherError,
    HttpRequestTooManyRequests,
    TitleExtractError,
    KeywordExtractError,
    MetaDescriptionExtractError,
    LinkedInSlugExtractError,
    ProcessUrlTimeout,
    // DNS errors
    DnsNsLookupError,
    DnsTxtLookupError,
    DnsMxLookupError,
    // TLS errors
    TlsCertificateError,
    // Technology detection errors
    TechnologyDetectionError,
}

impl ErrorType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorType::HttpRequestBuilderError => "HTTP request builder error",
            ErrorType::HttpRequestRedirectError => "HTTP request redirect error",
            ErrorType::HttpRequestStatusError => "HTTP request status error",
            ErrorType::HttpRequestTimeoutError => "HTTP request timeout error",
            ErrorType::HttpRequestRequestError => "HTTP request error",
            ErrorType::HttpRequestConnectError => "HTTP request connect error",
            ErrorType::HttpRequestBodyError => "HTTP request body error",
            ErrorType::HttpRequestDecodeError => "HTTP request decode error",
            ErrorType::HttpRequestOtherError => "HTTP request other error",
            ErrorType::HttpRequestTooManyRequests => "Too many requests",
            ErrorType::TitleExtractError => "Title extract error",
            ErrorType::KeywordExtractError => "Keyword extract error",
            ErrorType::MetaDescriptionExtractError => "Meta description extract error",
            ErrorType::LinkedInSlugExtractError => "LinkedIn slug extract error",
            ErrorType::ProcessUrlTimeout => "Process URL timeout",
            ErrorType::DnsNsLookupError => "DNS NS lookup error",
            ErrorType::DnsTxtLookupError => "DNS TXT lookup error",
            ErrorType::DnsMxLookupError => "DNS MX lookup error",
            ErrorType::TlsCertificateError => "TLS certificate error",
            ErrorType::TechnologyDetectionError => "Technology detection error",
        }
    }
}

/// Thread-safe error statistics tracker.
///
/// Tracks the count of each error type using atomic counters, allowing concurrent
/// access from multiple tasks. All error types are initialized to zero on creation.
///
/// # Thread Safety
///
/// This struct is thread-safe and can be shared across multiple tasks using `Arc`.
pub struct ErrorStats {
    errors: HashMap<ErrorType, AtomicUsize>,
}

impl ErrorStats {
    pub fn new() -> Self {
        let mut errors = HashMap::new();
        for error in ErrorType::iter() {
            errors.insert(error, AtomicUsize::new(0));
        }
        ErrorStats { errors }
    }

    pub fn increment(&self, error: ErrorType) {
        // All ErrorType variants are initialized in new(), so unwrap() is safe
        self.errors
            .get(&error)
            .unwrap()
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_count(&self, error: ErrorType) -> usize {
        // All ErrorType variants are initialized in new(), so unwrap() is safe
        self.errors.get(&error).unwrap().load(Ordering::SeqCst)
    }
}

/// Creates an exponential backoff retry strategy.
///
/// Returns a retry strategy configured with:
/// - Initial delay: `RETRY_INITIAL_DELAY_MS` milliseconds
/// - Backoff factor: `RETRY_FACTOR` (doubles delay each retry)
/// - Maximum delay: `RETRY_MAX_DELAY_SECS` seconds
///
/// # Returns
///
/// An `ExponentialBackoff` strategy ready for use with `tokio_retry::Retry`.
pub fn get_retry_strategy() -> ExponentialBackoff {
    ExponentialBackoff::from_millis(crate::config::RETRY_INITIAL_DELAY_MS)
        .factor(crate::config::RETRY_FACTOR) // Double the delay with each retry
        .max_delay(Duration::from_secs(crate::config::RETRY_MAX_DELAY_SECS)) // Maximum delay
}

/// Updates error statistics based on a `reqwest::Error`.
///
/// Analyzes the error and increments the appropriate `ErrorType` counter.
/// Handles both HTTP status errors (e.g., 429 Too Many Requests) and network-level
/// errors (timeouts, connection failures, etc.).
///
/// # Arguments
///
/// * `error_stats` - The error statistics tracker to update
/// * `error` - The `reqwest::Error` to categorize and record
pub async fn update_error_stats(error_stats: &ErrorStats, error: &reqwest::Error) {
    let error_type = match error.status() {
        // When the error contains a status code, match on it
        Some(status) if status.is_client_error() => match status.as_u16() {
            429 => ErrorType::HttpRequestTooManyRequests,
            _ => ErrorType::HttpRequestOtherError,
        },
        Some(status) if status.is_server_error() => ErrorType::HttpRequestOtherError,
        _ => {
            // For non-status errors, check the error type
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
    };

    error_stats.increment(error_type);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_stats_initialization() {
        let stats = ErrorStats::new();
        // All error types should be initialized to 0
        for error_type in ErrorType::iter() {
            assert_eq!(stats.get_count(error_type), 0);
        }
    }

    #[test]
    fn test_error_stats_increment() {
        let stats = ErrorStats::new();
        stats.increment(ErrorType::TitleExtractError);
        assert_eq!(stats.get_count(ErrorType::TitleExtractError), 1);
        assert_eq!(stats.get_count(ErrorType::KeywordExtractError), 0);
    }

    #[test]
    fn test_error_stats_multiple_increments() {
        let stats = ErrorStats::new();
        stats.increment(ErrorType::TitleExtractError);
        stats.increment(ErrorType::TitleExtractError);
        stats.increment(ErrorType::TitleExtractError);
        assert_eq!(stats.get_count(ErrorType::TitleExtractError), 3);
    }
}
