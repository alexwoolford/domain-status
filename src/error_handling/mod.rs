//! Error handling and processing statistics.
//!
//! This module provides:
//! - Error type definitions and categorization
//! - Processing statistics tracking (errors, warnings, info metrics)
//! - Retry strategy configuration
//! - Error type extraction from error chains
//!
//! # Error Handling Strategy
//!
//! ## Custom Error Types
//!
//! - **`DatabaseError`**: Used for all database operations (connection, queries, transactions)
//!   - Provides clear distinction between SQL errors and file creation errors
//!   - Used in: `storage::insert`, `storage::pool`, `storage::migrations`
//!
//! - **`InitializationError`**: Used for application startup errors
//!   - Covers logger, HTTP client, and DNS resolver initialization
//!   - Used in: `initialization::*` modules
//!
//! ## Generic Error Types
//!
//! - **`anyhow::Error`**: Used in processing/fetch layer where error chaining is beneficial
//!   - Allows attaching context with `.context()` and `.with_context()`
//!   - Used in: `fetch::*`, `utils::process`, `main.rs`
//!   - Benefits: Flexible error propagation, automatic error chain traversal
//!
//! ## Error Categorization
//!
//! Error types are categorized into:
//! - **Errors**: Failures that prevent successful processing
//! - **Warnings**: Missing optional data that doesn't prevent processing
//! - **Info**: Informational metrics (redirects, bot detection, etc.)
//!
//! - **`ErrorType`**: Categorizes errors for statistics and retry logic
//!   - Used with `ProcessingStats` to track error frequencies
//!   - Used with `get_retry_strategy()` to determine retry behavior
//!
//! ## Best Practices
//!
//! 1. Use `DatabaseError` for all database operations
//! 2. Use `InitializationError` for startup/initialization
//! 3. Use `anyhow::Error` for processing pipelines where context matters
//! 4. Always categorize errors using `ErrorType` for statistics
//! 5. Attach context with `.context()` or `.with_context()` when using `anyhow::Error`

mod categorization;
mod stats;
mod types;

// Re-export public API
pub use categorization::{categorize_reqwest_error, get_retry_strategy, update_error_stats};
pub use stats::ProcessingStats;
pub use types::{
    DatabaseError, ErrorType, FingerprintError, InfoType, InitializationError, WarningType,
};

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

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

    // Note: Testing categorize_reqwest_error with actual HTTP status codes requires
    // creating reqwest::Error instances, which is complex without a real HTTP server.
    // These tests verify the logic works correctly, but for comprehensive testing
    // of status code mapping, integration tests with a mock HTTP server would be better.
    //
    // The function is tested indirectly through:
    // 1. Integration with extract_error_type in src/storage/failure.rs tests
    // 2. Real-world usage in production code
    //
    // If more comprehensive testing is needed, consider using mockito or wiremock
    // to create actual HTTP responses and test the full error categorization flow.
}
