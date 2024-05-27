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
pub enum InitializationError {
    /// Error initializing the logger.
    #[error("Logger initialization error: {0}")]
    LoggerError(#[from] SetLoggerError),

    /// Error initializing the HTTP client.
    #[error("HTTP client initialization error: {0}")]
    HttpClientError(#[from] ReqwestError),
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
    HttpRequestTooManyRedirects,
    TitleExtractError,
    KeywordExtractError,
    MetaDescriptionExtractError,
    LinkedInSlugExtractError,
    ProcessUrlTimeout,
}

impl ErrorType {
    pub fn to_string(&self) -> &'static str {
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
            ErrorType::HttpRequestTooManyRedirects => "Too many redirects",
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
        if let Some(counter) = self.errors.get(&error) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn get_count(&self, error: ErrorType) -> usize {
        if let Some(counter) = self.errors.get(&error) {
            counter.load(Ordering::SeqCst)
        } else {
            0
        }
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

        if self.operation_count.load(Ordering::SeqCst) % LOGGING_INTERVAL == 0 {
            let error_rate = self.calculate_error_rate();

            self.error_rate.store(error_rate as usize, Ordering::SeqCst);

            let total_errors = self.error_stats.total_error_count();

            if error_rate > self.error_rate_threshold {
                // increase backoff time
                let sleep_duration = Duration::from_secs_f64((error_rate / 5.0).max(1.0));
                warn!("Throttled; error rate of {:.2}% has exceeded the set threshold. There were {} errors out of {} operations. Backoff time is {:.2} seconds.",
                    error_rate, total_errors, self.operation_count.load(Ordering::SeqCst), sleep_duration.as_secs_f64());
                tokio::time::sleep(sleep_duration).await;
            }
        }
    }

    fn calculate_error_rate(&self) -> f64 {
        let total_errors = self.error_stats.total_error_count();
        let error_rate = (total_errors as f64
            / f64::max(
                total_errors as f64,
                self.operation_count.load(Ordering::SeqCst) as f64,
            ))
            * 100.0;
        error_rate
    }
}

pub fn get_retry_strategy() -> ExponentialBackoff {
    ExponentialBackoff::from_millis(1000)
        .factor(2) // Double the delay with each retry
        .max_delay(Duration::from_secs(20)) // Maximum delay of 20 seconds
}

pub async fn update_error_stats(error_stats: &ErrorStats, error: &reqwest::Error) {
    let error_type = match error.status() {
        // When the error contains a status code, match on it
        Some(status) if status.is_client_error() => match status.as_u16() {
            429 => ErrorType::HttpRequestTooManyRedirects,
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
