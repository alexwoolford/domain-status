//! Error type definitions.
//!
//! This module defines all error, warning, and info types used throughout the application.

use log::SetLoggerError;
use reqwest::Error as ReqwestError;
use strum_macros::EnumIter as EnumIterMacro;
use thiserror::Error;

/// Errors that occur before or during scan setup (config, init, bind).
///
/// Use this to separate "startup" failures from "runtime" failures during the main loop,
/// enabling consistent logging and optional exit-code differentiation.
///
/// Marked `#[non_exhaustive]` so adding new failure modes is not a breaking
/// change. Downstream `match` expressions must include a `_ =>` arm.
///
/// `Anyhow` remains as a catch-all for startup steps (notably
/// `init_scan_resources`, which composes many subsystems and uses
/// `anyhow::Error` internally); typed variants exist for the cases where
/// callers most often want to branch (config validation, initialization,
/// status-server lifecycle).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StartupError {
    /// Configuration validation failed.
    #[error("{0}")]
    ConfigValidation(#[from] crate::config::ConfigValidationError),

    /// An initialization step failed (logger, HTTP client, DNS resolver).
    #[error("{0}")]
    Initialization(#[from] InitializationError),

    /// Status server bind / serve / background-task failure.
    #[error("{0}")]
    StatusServer(#[from] crate::status_server::StatusServerLifecycleError),

    /// IO error with context (e.g. path or operation name).
    #[error("{0}\ncaused by: {1}")]
    Io(String, std::io::Error),

    /// Other startup failure (e.g. `init_scan_resources`).
    ///
    /// Callers wanting to branch on a specific cause should walk
    /// `std::error::Error::source()` (or `anyhow::Error::chain()`) — the
    /// underlying `anyhow::Error` preserves the source chain.
    #[error("{0}")]
    Anyhow(#[from] anyhow::Error),
}

/// Error returned by `run_scan`: either during setup (startup) or during the main loop (runtime).
///
/// Marked `#[non_exhaustive]` so adding new categories is not a breaking change.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RunScanError {
    /// Failure during scan setup (config validation, resource init, status server bind).
    #[error("Startup error: {0}")]
    Startup(#[from] StartupError),

    /// Failure during the scan loop or finalization.
    #[error("Runtime error: {0}")]
    Runtime(#[from] anyhow::Error),
}

/// Error types for initialization failures.
///
/// Marked `#[non_exhaustive]` so adding new init failure modes is not breaking.
#[derive(Error, Debug)]
#[allow(clippy::enum_variant_names)] // All variants end with "Error" by convention
#[non_exhaustive]
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
    DnsResolverError(String),
}

/// Error types for database operations.
///
/// Marked `#[non_exhaustive]` so adding new DB failure modes (e.g. migration,
/// pool, lock-contention) is not a breaking change.
///
/// `FileCreationError` carries a `#[source]` so the underlying `io::Error` /
/// `JoinError` / `sqlx::Error` is reachable through `std::error::Error::source()`
/// rather than flattened into a single `String` (the previous tuple-variant
/// design lost all of that diagnostic structure when the chain was walked).
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum DatabaseError {
    /// Error creating, opening, or initializing the database file.
    ///
    /// `context` describes the high-level operation (`"creating directory"`,
    /// `"opening database file"`, etc.); `source` is the underlying error so
    /// callers can `downcast_ref::<io::Error>()` if they need to branch on the
    /// kind (e.g. `PermissionDenied`).
    #[error("Database file creation error: {context}")]
    FileCreationError {
        /// High-level description of which step failed.
        context: String,
        /// The underlying error (preserved as a source so error-chain walks
        /// reach the real `io::Error` / `JoinError` / `sqlx::Error`).
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// SQL execution error.
    #[error("SQL error: {0}")]
    SqlError(#[from] sqlx::Error),
}

/// Error types for `run_migrations`.
///
/// Distinguishes the underlying failure mode (sqlx migrator error, on-disk
/// extraction failure, blocking-task panic) so callers can branch on the
/// cause rather than parsing a single opaque message. Each variant exposes
/// the original error via `#[source]` for chain walks.
///
/// Marked `#[non_exhaustive]` so adding new failure modes is not breaking.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum MigrationError {
    /// `SQLx` migrator failed to load or execute a migration.
    #[error("migration execution failed")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    /// On-disk extraction of embedded migrations failed (`create_dir_all`,
    /// write to `TempDir`, etc).
    #[error("failed to extract embedded migrations to {context}")]
    ExtractIo {
        /// Where extraction was happening (e.g. the temp-dir path).
        context: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// `tokio::task::spawn_blocking` for the extraction step panicked or
    /// was cancelled.
    #[error("background task panicked while extracting embedded migrations")]
    BlockingTask(#[from] tokio::task::JoinError),
}

/// Error types for technology fingerprinting operations.
///
/// Distinguishes between configuration errors (ruleset not loaded) and
/// runtime detection failures (background-task panic, etc).
///
/// Marked `#[non_exhaustive]` so adding new failure modes is not breaking.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum FingerprintError {
    /// The fingerprint ruleset has not been initialized.
    ///
    /// This indicates a programming error -- `init_ruleset()` must be called
    /// before `detect_technologies()`.
    #[error("Ruleset not initialized. Call init_ruleset() first")]
    RulesetNotInitialized,

    /// The CPU-bound detection task on `tokio::spawn_blocking` panicked or
    /// was cancelled. Exposed as a typed source so callers can branch on
    /// the cause via `std::error::Error::source()` rather than parsing an
    /// opaque `anyhow::Error` message.
    #[error("Background detection task panicked")]
    DetectionTaskJoin(#[from] tokio::task::JoinError),
}

/// Types of errors that can occur during URL processing.
///
/// This enum categorizes actual error conditions - failures that prevent successful
/// processing or indicate system/network problems.
///
/// Marked `#[non_exhaustive]` so adding new error categories (e.g. for new
/// status codes or DNS record types) is not a semver-breaking change.
/// Downstream `match` expressions must include a `_ =>` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIterMacro, enum_map::Enum)]
#[non_exhaustive]
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
    DnsForwardLookupError,
    DnsNsLookupError,
    DnsTxtLookupError,
    DnsMxLookupError,
    DnsCnameLookupError,
    DnsAaaaLookupError,
    DnsCaaLookupError,
    // TLS errors
    TlsCertificateError,
    // Technology detection errors
    TechnologyDetectionError,
}

/// Types of warnings that can occur during URL processing.
///
/// Warnings indicate missing optional data that doesn't prevent successful
/// processing but is worth tracking.
///
/// Marked `#[non_exhaustive]` so adding new warning categories is not breaking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIterMacro, enum_map::Enum)]
#[allow(clippy::enum_variant_names)] // All variants start with "Missing" by design
#[non_exhaustive]
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
///
/// Marked `#[non_exhaustive]` so adding new info categories is not breaking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIterMacro, enum_map::Enum)]
#[non_exhaustive]
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
    pub fn as_str(self) -> &'static str {
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
            ErrorType::DnsForwardLookupError => "DNS forward lookup error",
            ErrorType::DnsNsLookupError => "DNS NS lookup error",
            ErrorType::DnsTxtLookupError => "DNS TXT lookup error",
            ErrorType::DnsMxLookupError => "DNS MX lookup error",
            ErrorType::DnsCnameLookupError => "DNS CNAME lookup error",
            ErrorType::DnsAaaaLookupError => "DNS AAAA lookup error",
            ErrorType::DnsCaaLookupError => "DNS CAA lookup error",
            ErrorType::TlsCertificateError => "TLS certificate error",
            ErrorType::TechnologyDetectionError => "Technology detection error",
        }
    }
}

impl WarningType {
    /// Returns a human-readable string representation of the warning type.
    pub fn as_str(self) -> &'static str {
        match self {
            WarningType::MissingMetaKeywords => "Missing meta keywords",
            WarningType::MissingMetaDescription => "Missing meta description",
            WarningType::MissingTitle => "Missing title",
        }
    }
}

impl InfoType {
    /// Returns a human-readable string representation of the info type.
    pub fn as_str(self) -> &'static str {
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

    /// Regression guard for `DatabaseError::FileCreationError`'s source chain.
    ///
    /// The previous tuple variant `FileCreationError(String)` flattened any
    /// underlying error into `format!("{e}")` so error-chain walks (e.g.
    /// `anyhow::Error::chain()`, `print_io_error_hint_if_applicable`) lost the
    /// concrete `io::Error` they were trying to find. The struct variant uses
    /// `#[source]` so the wrapped error stays reachable. This test fails if a
    /// future refactor accidentally reverts to a string-only representation.
    #[test]
    fn test_file_creation_error_preserves_source_chain() {
        let inner = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "owner-only directory rejected the call",
        );
        let err = DatabaseError::FileCreationError {
            context: "Failed to create database directory for /etc/secret/db".to_string(),
            source: Box::new(inner),
        };
        // Display still surfaces the high-level context.
        let display = format!("{err}");
        assert!(
            display.contains("Failed to create database directory"),
            "expected context in Display, got: {display}"
        );
        // The underlying io::Error must be reachable through the source chain
        // and `downcast_ref` must succeed — that is what
        // `print_io_error_hint_if_applicable` (and any external matcher) relies on.
        let source = std::error::Error::source(&err)
            .expect("FileCreationError must expose its underlying source");
        let io_err = source
            .downcast_ref::<std::io::Error>()
            .expect("source should downcast to io::Error");
        assert_eq!(io_err.kind(), std::io::ErrorKind::PermissionDenied);
    }

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
}
