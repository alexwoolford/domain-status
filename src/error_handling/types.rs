//! Error type definitions.
//!
//! This module defines all error, warning, and info types used throughout the application.

use log::SetLoggerError;
use reqwest::Error as ReqwestError;
use strum_macros::EnumIter as EnumIterMacro;
use thiserror::Error;

/// Error types for initialization failures.
#[derive(Error, Debug)]
#[allow(clippy::enum_variant_names)] // All variants end with "Error" by convention
pub enum InitializationError {
    /// Error initializing the logger.
    #[error("Logger initialization error: {0}")]
    LoggerError(#[from] SetLoggerError),

    /// Error initializing the logger with custom message (e.g., file creation).
    #[error("Logger initialization error: {0}")]
    LoggerSetupError(String),

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

/// Error types for technology fingerprinting operations.
///
/// Distinguishes between configuration errors (ruleset not loaded) and
/// runtime detection failures (pattern compilation, matching errors).
#[derive(Error, Debug)]
pub enum FingerprintError {
    /// The fingerprint ruleset has not been initialized.
    ///
    /// This indicates a programming error -- `init_ruleset()` must be called
    /// before `detect_technologies()`.
    #[error("Ruleset not initialized. Call init_ruleset() first")]
    RulesetNotInitialized,

    /// A detection-phase error (e.g., regex compilation failure, pattern matching error).
    #[error("Technology detection failed: {0}")]
    DetectionFailed(#[from] anyhow::Error),
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
    // Specific HTTP status code errors (common ones for better debugging)
    HttpRequestBadRequest,          // 400 Bad Request
    HttpRequestUnauthorized,        // 401 Unauthorized
    HttpRequestNotFound,            // 404 Not Found
    HttpRequestInternalServerError, // 500 Internal Server Error
    HttpRequestBadGateway,          // 502 Bad Gateway
    HttpRequestServiceUnavailable,  // 503 Service Unavailable
    HttpRequestGatewayTimeout,      // 504 Gateway Timeout
    // Note: Less common status codes (406, 521, etc.) are categorized as HttpRequestOtherError
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
    BotDetection403, // Received 403 (likely bot detection)
    // Other notable events
    MultipleRedirects, // Multiple redirects in chain
}

impl std::fmt::Display for ErrorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
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
            ErrorType::HttpRequestInternalServerError => "Internal Server Error (500)",
            ErrorType::HttpRequestBadGateway => "Bad Gateway (502)",
            ErrorType::HttpRequestServiceUnavailable => "Service Unavailable (503)",
            ErrorType::HttpRequestGatewayTimeout => "Gateway Timeout (504)",
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
    /// Returns a human-readable string representation of the warning type.
    #[allow(dead_code)] // May be used for future reporting features
    pub fn as_str(&self) -> &'static str {
        match self {
            WarningType::MissingMetaKeywords => "Missing meta keywords",
            WarningType::MissingMetaDescription => "Missing meta description",
            WarningType::MissingTitle => "Missing title",
        }
    }
}

impl InfoType {
    /// Returns a human-readable string representation of the info type.
    #[allow(dead_code)] // May be used for future reporting features
    pub fn as_str(&self) -> &'static str {
        match self {
            InfoType::HttpRedirect => "HTTP redirect",
            InfoType::HttpsRedirect => "HTTP to HTTPS redirect",
            InfoType::BotDetection403 => "Bot detection (403)",
            InfoType::MultipleRedirects => "Multiple redirects",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    #[test]
    fn test_error_type_as_str() {
        // Test a few error types to verify as_str() works
        assert_eq!(
            ErrorType::HttpRequestTimeoutError.as_str(),
            "HTTP request timeout error"
        );
        assert_eq!(
            ErrorType::HttpRequestBotDetectionError.as_str(),
            "Bot detection (403 Forbidden)"
        );
        assert_eq!(ErrorType::DnsNsLookupError.as_str(), "DNS NS lookup error");
        assert_eq!(ErrorType::HttpRequestNotFound.as_str(), "Not Found (404)");
    }

    #[test]
    fn test_warning_type_as_str() {
        assert_eq!(
            WarningType::MissingMetaDescription.as_str(),
            "Missing meta description"
        );
        assert_eq!(WarningType::MissingTitle.as_str(), "Missing title");
        assert_eq!(
            WarningType::MissingMetaKeywords.as_str(),
            "Missing meta keywords"
        );
    }

    #[test]
    fn test_info_type_as_str() {
        assert_eq!(InfoType::HttpRedirect.as_str(), "HTTP redirect");
        assert_eq!(InfoType::HttpsRedirect.as_str(), "HTTP to HTTPS redirect");
        assert_eq!(InfoType::BotDetection403.as_str(), "Bot detection (403)");
        assert_eq!(InfoType::MultipleRedirects.as_str(), "Multiple redirects");
    }

    #[test]
    fn test_all_error_types_have_string_representation() {
        // Verify all error types have non-empty string representations
        for error_type in ErrorType::iter() {
            let str_repr = error_type.as_str();
            assert!(
                !str_repr.is_empty(),
                "{:?} should have non-empty string",
                error_type
            );
        }
    }

    #[test]
    fn test_all_warning_types_have_string_representation() {
        // Verify all warning types have non-empty string representations
        for warning_type in WarningType::iter() {
            let str_repr = warning_type.as_str();
            assert!(
                !str_repr.is_empty(),
                "{:?} should have non-empty string",
                warning_type
            );
        }
    }

    #[test]
    fn test_all_info_types_have_string_representation() {
        // Verify all info types have non-empty string representations
        for info_type in InfoType::iter() {
            let str_repr = info_type.as_str();
            assert!(
                !str_repr.is_empty(),
                "{:?} should have non-empty string",
                info_type
            );
        }
    }

    #[test]
    fn test_error_type_equality() {
        // Verify ErrorType implements PartialEq correctly
        assert_eq!(
            ErrorType::HttpRequestTimeoutError,
            ErrorType::HttpRequestTimeoutError
        );
        assert_ne!(
            ErrorType::HttpRequestTimeoutError,
            ErrorType::DnsNsLookupError
        );
    }

    #[test]
    fn test_warning_type_equality() {
        // Verify WarningType implements PartialEq correctly
        assert_eq!(WarningType::MissingTitle, WarningType::MissingTitle);
        assert_ne!(
            WarningType::MissingTitle,
            WarningType::MissingMetaDescription
        );
    }

    #[test]
    fn test_info_type_equality() {
        // Verify InfoType implements PartialEq correctly
        assert_eq!(InfoType::HttpRedirect, InfoType::HttpRedirect);
        assert_ne!(InfoType::HttpRedirect, InfoType::HttpsRedirect);
    }
}
