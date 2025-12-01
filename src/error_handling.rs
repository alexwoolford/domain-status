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
/// This enum categorizes actual error conditions - failures that prevent successful
/// processing or indicate system/network problems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIterMacro)]
pub enum ErrorType {
    // HTTP/Network errors
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
    HttpRequestBotDetectionError, // 403 Forbidden - typically bot detection
    // Specific HTTP status code errors
    HttpRequestBadRequest,        // 400 Bad Request
    HttpRequestUnauthorized,       // 401 Unauthorized
    HttpRequestNotFound,           // 404 Not Found
    HttpRequestNotAcceptable,     // 406 Not Acceptable
    HttpRequestInternalServerError, // 500 Internal Server Error
    HttpRequestBadGateway,         // 502 Bad Gateway
    HttpRequestServiceUnavailable, // 503 Service Unavailable
    HttpRequestGatewayTimeout,     // 504 Gateway Timeout
    HttpRequestCloudflareError,    // 521 Cloudflare Web Server Down
    // Data extraction errors (only for required data)
    TitleExtractError, // Missing title - could be an error if we expect one
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

/// Types of warnings that can occur during URL processing.
///
/// Warnings indicate missing optional data that doesn't prevent successful
/// processing but is worth tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIterMacro)]
#[allow(clippy::enum_variant_names)] // All variants start with "Missing" by design
pub enum WarningType {
    // Missing optional metadata
    MissingMetaKeywords,    // Meta keywords tag is missing
    MissingMetaDescription, // Meta description tag is missing (optional but recommended for SEO)
    MissingTitle,           // Title tag is missing (unusual but not necessarily an error)
}

/// Types of informational metrics that can occur during URL processing.
///
/// Info metrics track useful data points that aren't errors or warnings,
/// such as redirects, bot detection, or other notable events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIterMacro)]
pub enum InfoType {
    // HTTP redirects
    HttpRedirect,  // HTTP redirect occurred (301, 302, etc.)
    HttpsRedirect, // HTTP to HTTPS redirect
    // Bot detection
    BotDetection403,              // Received 403 (likely bot detection)
    BotDetectionDifferentContent, // Received different content (likely bot detection)
    // Other notable events
    MultipleRedirects, // Multiple redirects in chain
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
            ErrorType::HttpRequestBotDetectionError => "Bot detection (403 Forbidden)",
            ErrorType::HttpRequestBadRequest => "Bad Request (400)",
            ErrorType::HttpRequestUnauthorized => "Unauthorized (401)",
            ErrorType::HttpRequestNotFound => "Not Found (404)",
            ErrorType::HttpRequestNotAcceptable => "Not Acceptable (406)",
            ErrorType::HttpRequestInternalServerError => "Internal Server Error (500)",
            ErrorType::HttpRequestBadGateway => "Bad Gateway (502)",
            ErrorType::HttpRequestServiceUnavailable => "Service Unavailable (503)",
            ErrorType::HttpRequestGatewayTimeout => "Gateway Timeout (504)",
            ErrorType::HttpRequestCloudflareError => "Cloudflare Error (521)",
            ErrorType::TitleExtractError => "Title extract error",
            ErrorType::ProcessUrlTimeout => "Process URL timeout",
            ErrorType::DnsNsLookupError => "DNS NS lookup error",
            ErrorType::DnsTxtLookupError => "DNS TXT lookup error",
            ErrorType::DnsMxLookupError => "DNS MX lookup error",
            ErrorType::TlsCertificateError => "TLS certificate error",
            ErrorType::TechnologyDetectionError => "Technology detection error",
        }
    }
}

impl WarningType {
    pub fn as_str(&self) -> &'static str {
        match self {
            WarningType::MissingMetaKeywords => "Missing meta keywords",
            WarningType::MissingMetaDescription => "Missing meta description",
            WarningType::MissingTitle => "Missing title",
        }
    }
}

impl InfoType {
    pub fn as_str(&self) -> &'static str {
        match self {
            InfoType::HttpRedirect => "HTTP redirect",
            InfoType::HttpsRedirect => "HTTP to HTTPS redirect",
            InfoType::BotDetection403 => "Bot detection (403)",
            InfoType::BotDetectionDifferentContent => "Bot detection (different content)",
            InfoType::MultipleRedirects => "Multiple redirects",
        }
    }
}

/// Thread-safe processing statistics tracker.
///
/// Tracks errors, warnings, and informational metrics using atomic counters,
/// allowing concurrent access from multiple tasks. All types are initialized
/// to zero on creation.
///
/// # Categories
///
/// - **Errors**: Actual failures that prevent successful processing
/// - **Warnings**: Missing optional data
/// - **Info**: Notable events that aren't errors or warnings
///
/// # Thread Safety
///
/// This struct is thread-safe and can be shared across multiple tasks using `Arc`.
pub struct ProcessingStats {
    errors: HashMap<ErrorType, AtomicUsize>,
    warnings: HashMap<WarningType, AtomicUsize>,
    info: HashMap<InfoType, AtomicUsize>,
}

impl ProcessingStats {
    pub fn new() -> Self {
        let mut errors = HashMap::new();
        for error in ErrorType::iter() {
            errors.insert(error, AtomicUsize::new(0));
        }

        let mut warnings = HashMap::new();
        for warning in WarningType::iter() {
            warnings.insert(warning, AtomicUsize::new(0));
        }

        let mut info = HashMap::new();
        for info_type in InfoType::iter() {
            info.insert(info_type, AtomicUsize::new(0));
        }

        ProcessingStats {
            errors,
            warnings,
            info,
        }
    }

    /// Increment an error counter.
    pub fn increment_error(&self, error: ErrorType) {
        self.errors
            .get(&error)
            .unwrap()
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment a warning counter.
    pub fn increment_warning(&self, warning: WarningType) {
        self.warnings
            .get(&warning)
            .unwrap()
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment an info counter.
    #[allow(dead_code)] // Reserved for future use (redirects, bot detection, etc.)
    pub fn increment_info(&self, info_type: InfoType) {
        self.info
            .get(&info_type)
            .unwrap()
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get the count for an error type.
    pub fn get_error_count(&self, error: ErrorType) -> usize {
        self.errors.get(&error).unwrap().load(Ordering::SeqCst)
    }

    /// Get the count for a warning type.
    pub fn get_warning_count(&self, warning: WarningType) -> usize {
        self.warnings.get(&warning).unwrap().load(Ordering::SeqCst)
    }

    /// Get the count for an info type.
    pub fn get_info_count(&self, info_type: InfoType) -> usize {
        self.info.get(&info_type).unwrap().load(Ordering::SeqCst)
    }

    /// Get total error count across all error types.
    pub fn total_errors(&self) -> usize {
        ErrorType::iter().map(|e| self.get_error_count(e)).sum()
    }

    /// Get total warning count across all warning types.
    pub fn total_warnings(&self) -> usize {
        WarningType::iter().map(|w| self.get_warning_count(w)).sum()
    }

    /// Get total info count across all info types.
    pub fn total_info(&self) -> usize {
        InfoType::iter().map(|i| self.get_info_count(i)).sum()
    }
}

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
    let error_type = match error.status() {
        // When the error contains a status code, match on it
        Some(status) if status.is_client_error() => match status.as_u16() {
            400 => ErrorType::HttpRequestBadRequest,
            401 => ErrorType::HttpRequestUnauthorized,
            403 => ErrorType::HttpRequestBotDetectionError,
            404 => ErrorType::HttpRequestNotFound,
            406 => ErrorType::HttpRequestNotAcceptable,
            429 => ErrorType::HttpRequestTooManyRequests,
            _ => ErrorType::HttpRequestOtherError,
        },
        Some(status) if status.is_server_error() => match status.as_u16() {
            500 => ErrorType::HttpRequestInternalServerError,
            502 => ErrorType::HttpRequestBadGateway,
            503 => ErrorType::HttpRequestServiceUnavailable,
            504 => ErrorType::HttpRequestGatewayTimeout,
            521 => ErrorType::HttpRequestCloudflareError,
            _ => ErrorType::HttpRequestOtherError,
        },
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

    stats.increment_error(error_type);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processing_stats_initialization() {
        let stats = ProcessingStats::new();
        // All error types should be initialized to 0
        for error_type in ErrorType::iter() {
            assert_eq!(stats.get_error_count(error_type), 0);
        }
        // All warning types should be initialized to 0
        for warning_type in WarningType::iter() {
            assert_eq!(stats.get_warning_count(warning_type), 0);
        }
        // All info types should be initialized to 0
        for info_type in InfoType::iter() {
            assert_eq!(stats.get_info_count(info_type), 0);
        }
    }

    #[test]
    fn test_processing_stats_increment() {
        let stats = ProcessingStats::new();
        stats.increment_error(ErrorType::TitleExtractError);
        assert_eq!(stats.get_error_count(ErrorType::TitleExtractError), 1);

        stats.increment_warning(WarningType::MissingMetaDescription);
        assert_eq!(
            stats.get_warning_count(WarningType::MissingMetaDescription),
            1
        );

        stats.increment_info(InfoType::HttpRedirect);
        assert_eq!(stats.get_info_count(InfoType::HttpRedirect), 1);
    }

    #[test]
    fn test_processing_stats_multiple_increments() {
        let stats = ProcessingStats::new();
        stats.increment_error(ErrorType::TitleExtractError);
        stats.increment_error(ErrorType::TitleExtractError);
        stats.increment_error(ErrorType::TitleExtractError);
        assert_eq!(stats.get_error_count(ErrorType::TitleExtractError), 3);
    }

    #[test]
    fn test_processing_stats_totals() {
        let stats = ProcessingStats::new();
        stats.increment_error(ErrorType::TitleExtractError);
        stats.increment_error(ErrorType::HttpRequestTimeoutError);
        stats.increment_warning(WarningType::MissingMetaDescription);
        stats.increment_info(InfoType::HttpRedirect);

        assert_eq!(stats.total_errors(), 2);
        assert_eq!(stats.total_warnings(), 1);
        assert_eq!(stats.total_info(), 1);
    }
}
