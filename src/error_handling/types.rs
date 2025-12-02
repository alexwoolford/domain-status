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
    HttpRequestBadRequest,          // 400 Bad Request
    HttpRequestUnauthorized,        // 401 Unauthorized
    HttpRequestNotFound,            // 404 Not Found
    HttpRequestNotAcceptable,       // 406 Not Acceptable
    HttpRequestInternalServerError, // 500 Internal Server Error
    HttpRequestBadGateway,          // 502 Bad Gateway
    HttpRequestServiceUnavailable,  // 503 Service Unavailable
    HttpRequestGatewayTimeout,      // 504 Gateway Timeout
    HttpRequestCloudflareError,     // 521 Cloudflare Web Server Down
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
            InfoType::MultipleRedirects => "Multiple redirects",
        }
    }
}

