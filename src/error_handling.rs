use log::warn;
use log::SetLoggerError;
use reqwest::Error as ReqwestError;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use strum::IntoEnumIterator;
use strum_macros::EnumIter as EnumIterMacro;
use thiserror::Error;
use tokio_retry::strategy::ExponentialBackoff;

use crate::config::LOGGING_INTERVAL;

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
        }
    }
}

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

    pub fn total_error_count(&self) -> usize {
        self.errors
            .values()
            .map(|counter| counter.load(Ordering::SeqCst))
            .sum()
    }
}

#[derive(Clone)]
pub struct ErrorRateLimiter {
    pub error_stats: Arc<ErrorStats>,
    operation_count: Arc<AtomicUsize>,
    error_rate: Arc<AtomicUsize>,
    error_rate_threshold: f64,
}

impl ErrorRateLimiter {
    pub fn new(error_stats: Arc<ErrorStats>, error_rate_threshold: f64) -> Self {
        ErrorRateLimiter {
            error_stats,
            operation_count: Arc::new(AtomicUsize::new(0)),
            error_rate: Arc::new(AtomicUsize::new(0)),
            error_rate_threshold,
        }
    }

    pub async fn allow_operation(&self) {
        self.operation_count.fetch_add(1, Ordering::SeqCst);

        if self
            .operation_count
            .load(Ordering::SeqCst)
            .is_multiple_of(LOGGING_INTERVAL)
        {
            let error_rate = self.calculate_error_rate();

            self.error_rate.store(error_rate as usize, Ordering::SeqCst);

            let total_errors = self.error_stats.total_error_count();

            if error_rate > self.error_rate_threshold {
                // increase backoff time
                let sleep_duration = Duration::from_secs_f64(
                    (error_rate / crate::config::ERROR_RATE_BACKOFF_DIVISOR).max(1.0),
                );
                warn!("Throttled; error rate of {:.2}% has exceeded the set threshold. There were {} errors out of {} operations. Backoff time is {:.2} seconds.",
                    error_rate, total_errors, self.operation_count.load(Ordering::SeqCst), sleep_duration.as_secs_f64());
                tokio::time::sleep(sleep_duration).await;
            }
        }
    }

    fn calculate_error_rate(&self) -> f64 {
        let total_errors = self.error_stats.total_error_count();
        let total_operations = self.operation_count.load(Ordering::SeqCst);

        if total_operations == 0 {
            return 0.0;
        }

        (total_errors as f64 / total_operations as f64) * 100.0
    }
}

pub fn get_retry_strategy() -> ExponentialBackoff {
    ExponentialBackoff::from_millis(crate::config::RETRY_INITIAL_DELAY_MS)
        .factor(crate::config::RETRY_FACTOR) // Double the delay with each retry
        .max_delay(Duration::from_secs(crate::config::RETRY_MAX_DELAY_SECS)) // Maximum delay
}

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

    #[test]
    fn test_error_stats_total_count() {
        let stats = ErrorStats::new();
        stats.increment(ErrorType::TitleExtractError);
        stats.increment(ErrorType::KeywordExtractError);
        stats.increment(ErrorType::TitleExtractError);
        assert_eq!(stats.total_error_count(), 3);
    }

    #[test]
    fn test_error_rate_limiter_calculate_error_rate_zero_operations() {
        let stats = Arc::new(ErrorStats::new());
        let limiter = ErrorRateLimiter::new(stats, 60.0);
        // With zero operations, error rate should be 0
        assert_eq!(limiter.calculate_error_rate(), 0.0);
    }

    #[test]
    fn test_error_rate_limiter_calculate_error_rate_no_errors() {
        let stats = Arc::new(ErrorStats::new());
        let limiter = ErrorRateLimiter::new(stats, 60.0);
        // Simulate operations without errors
        limiter.operation_count.store(100, Ordering::SeqCst);
        assert_eq!(limiter.calculate_error_rate(), 0.0);
    }

    #[test]
    fn test_error_rate_limiter_calculate_error_rate_with_errors() {
        let stats = Arc::new(ErrorStats::new());
        let limiter = ErrorRateLimiter::new(stats.clone(), 60.0);
        // 10 errors out of 100 operations = 10%
        limiter.operation_count.store(100, Ordering::SeqCst);
        for _ in 0..10 {
            stats.increment(ErrorType::TitleExtractError);
        }
        assert_eq!(limiter.calculate_error_rate(), 10.0);
    }

    #[test]
    fn test_error_rate_limiter_calculate_error_rate_100_percent() {
        let stats = Arc::new(ErrorStats::new());
        let limiter = ErrorRateLimiter::new(stats.clone(), 60.0);
        // 50 errors out of 50 operations = 100%
        limiter.operation_count.store(50, Ordering::SeqCst);
        for _ in 0..50 {
            stats.increment(ErrorType::TitleExtractError);
        }
        assert_eq!(limiter.calculate_error_rate(), 100.0);
    }
}
