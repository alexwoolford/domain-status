//! Processing statistics tracking.
//!
//! This module provides thread-safe statistics tracking for errors, warnings,
//! and informational metrics during URL processing.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use strum::IntoEnumIterator;

use super::types::{ErrorType, InfoType, WarningType};

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
    ///
    /// Panics if `error` is not in the map (i.e. a new `ErrorType` variant was added
    /// but not added to `new()`). All variants are initialized in `new()`.
    pub fn increment_error(&self, error: ErrorType) {
        let counter = self
            .errors
            .get(&error)
            .expect("ErrorType missing from ProcessingStats::new()");
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment a warning counter.
    ///
    /// Panics if `warning` is not in the map (i.e. a new `WarningType` variant was added
    /// but not added to `new()`). All variants are initialized in `new()`.
    pub fn increment_warning(&self, warning: WarningType) {
        let counter = self
            .warnings
            .get(&warning)
            .expect("WarningType missing from ProcessingStats::new()");
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment an info counter.
    ///
    /// Panics if `info_type` is not in the map (i.e. a new `InfoType` variant was added
    /// but not added to `new()`). All variants are initialized in `new()`.
    pub fn increment_info(&self, info_type: InfoType) {
        let counter = self
            .info
            .get(&info_type)
            .expect("InfoType missing from ProcessingStats::new()");
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the count for an error type.
    ///
    /// Returns 0 if the error type is not in the map (should never happen; all variants
    /// are initialized in `new()`).
    pub fn get_error_count(&self, error: ErrorType) -> usize {
        self.errors
            .get(&error)
            .map(|c| c.load(Ordering::SeqCst))
            .unwrap_or(0)
    }

    /// Get the count for a warning type.
    ///
    /// Returns 0 if the warning type is not in the map (should never happen; all variants
    /// are initialized in `new()`).
    pub fn get_warning_count(&self, warning: WarningType) -> usize {
        self.warnings
            .get(&warning)
            .map(|c| c.load(Ordering::SeqCst))
            .unwrap_or(0)
    }

    /// Get the count for an info type.
    ///
    /// Returns 0 if the info type is not in the map (should never happen; all variants
    /// are initialized in `new()`).
    pub fn get_info_count(&self, info_type: InfoType) -> usize {
        self.info
            .get(&info_type)
            .map(|c| c.load(Ordering::SeqCst))
            .unwrap_or(0)
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

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    #[test]
    fn test_processing_stats_new() {
        let stats = ProcessingStats::new();

        // Verify all error types are initialized
        for error_type in ErrorType::iter() {
            assert_eq!(stats.get_error_count(error_type), 0);
        }

        // Verify all warning types are initialized
        for warning_type in WarningType::iter() {
            assert_eq!(stats.get_warning_count(warning_type), 0);
        }

        // Verify all info types are initialized
        for info_type in InfoType::iter() {
            assert_eq!(stats.get_info_count(info_type), 0);
        }

        // Verify totals are zero
        assert_eq!(stats.total_errors(), 0);
        assert_eq!(stats.total_warnings(), 0);
        assert_eq!(stats.total_info(), 0);
    }

    #[test]
    fn test_increment_error() {
        let stats = ProcessingStats::new();

        stats.increment_error(ErrorType::HttpRequestTimeoutError);
        assert_eq!(stats.get_error_count(ErrorType::HttpRequestTimeoutError), 1);
        assert_eq!(stats.total_errors(), 1);

        stats.increment_error(ErrorType::HttpRequestTimeoutError);
        assert_eq!(stats.get_error_count(ErrorType::HttpRequestTimeoutError), 2);
        assert_eq!(stats.total_errors(), 2);

        // Increment different error type
        stats.increment_error(ErrorType::DnsNsLookupError);
        assert_eq!(stats.get_error_count(ErrorType::DnsNsLookupError), 1);
        assert_eq!(stats.total_errors(), 3);
    }

    #[test]
    fn test_increment_warning() {
        let stats = ProcessingStats::new();

        stats.increment_warning(WarningType::MissingMetaDescription);
        assert_eq!(
            stats.get_warning_count(WarningType::MissingMetaDescription),
            1
        );
        assert_eq!(stats.total_warnings(), 1);

        stats.increment_warning(WarningType::MissingTitle);
        assert_eq!(stats.get_warning_count(WarningType::MissingTitle), 1);
        assert_eq!(stats.total_warnings(), 2);
    }

    #[test]
    fn test_increment_info() {
        let stats = ProcessingStats::new();

        stats.increment_info(InfoType::HttpRedirect);
        assert_eq!(stats.get_info_count(InfoType::HttpRedirect), 1);
        assert_eq!(stats.total_info(), 1);

        stats.increment_info(InfoType::HttpsRedirect);
        assert_eq!(stats.get_info_count(InfoType::HttpsRedirect), 1);
        assert_eq!(stats.total_info(), 2);
    }

    #[test]
    fn test_concurrent_increments() {
        use std::sync::Arc;
        use std::thread;

        let stats = Arc::new(ProcessingStats::new());
        let mut handles = Vec::new();

        // Spawn 10 threads, each incrementing the same error type 10 times
        for _ in 0..10 {
            let stats_clone = Arc::clone(&stats);
            let handle = thread::spawn(move || {
                for _ in 0..10 {
                    stats_clone.increment_error(ErrorType::HttpRequestTimeoutError);
                }
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Should have 100 total increments (10 threads * 10 increments)
        assert_eq!(
            stats.get_error_count(ErrorType::HttpRequestTimeoutError),
            100
        );
        assert_eq!(stats.total_errors(), 100);
    }

    #[test]
    fn test_multiple_error_types() {
        let stats = ProcessingStats::new();

        stats.increment_error(ErrorType::HttpRequestTimeoutError);
        stats.increment_error(ErrorType::DnsNsLookupError);
        stats.increment_error(ErrorType::TlsCertificateError);
        stats.increment_error(ErrorType::HttpRequestTimeoutError);

        assert_eq!(stats.get_error_count(ErrorType::HttpRequestTimeoutError), 2);
        assert_eq!(stats.get_error_count(ErrorType::DnsNsLookupError), 1);
        assert_eq!(stats.get_error_count(ErrorType::TlsCertificateError), 1);
        assert_eq!(stats.total_errors(), 4);
    }

    #[test]
    fn test_all_error_types_initialized() {
        let stats = ProcessingStats::new();

        // Verify every error type can be incremented and retrieved
        for error_type in ErrorType::iter() {
            stats.increment_error(error_type);
            assert_eq!(stats.get_error_count(error_type), 1);
        }

        // Total should equal number of error types
        let error_type_count = ErrorType::iter().count();
        assert_eq!(stats.total_errors(), error_type_count);
    }

    #[test]
    fn test_all_warning_types_initialized() {
        let stats = ProcessingStats::new();

        // Verify every warning type can be incremented and retrieved
        for warning_type in WarningType::iter() {
            stats.increment_warning(warning_type);
            assert_eq!(stats.get_warning_count(warning_type), 1);
        }

        // Total should equal number of warning types
        let warning_type_count = WarningType::iter().count();
        assert_eq!(stats.total_warnings(), warning_type_count);
    }

    #[test]
    fn test_all_info_types_initialized() {
        let stats = ProcessingStats::new();

        // Verify every info type can be incremented and retrieved
        for info_type in InfoType::iter() {
            stats.increment_info(info_type);
            assert_eq!(stats.get_info_count(info_type), 1);
        }

        // Total should equal number of info types
        let info_type_count = InfoType::iter().count();
        assert_eq!(stats.total_info(), info_type_count);
    }
}
