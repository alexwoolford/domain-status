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
    /// # Safety
    /// This should never panic if `ProcessingStats` is properly initialized via `new()`.
    /// All error types are initialized in the constructor. If a panic occurs, it indicates
    /// a bug in initialization or a missing enum variant.
    pub fn increment_error(&self, error: ErrorType) {
        if let Some(counter) = self.errors.get(&error) {
            counter.fetch_add(1, Ordering::Relaxed);
        } else {
            log::error!(
                "Attempted to increment error counter for {:?} which is not in the map. \
                 This indicates a bug in ProcessingStats initialization.",
                error
            );
            // Don't panic - log and continue to avoid crashing the application
        }
    }

    /// Increment a warning counter.
    ///
    /// # Safety
    /// This should never panic if `ProcessingStats` is properly initialized via `new()`.
    /// All warning types are initialized in the constructor. If a panic occurs, it indicates
    /// a bug in initialization or a missing enum variant.
    pub fn increment_warning(&self, warning: WarningType) {
        if let Some(counter) = self.warnings.get(&warning) {
            counter.fetch_add(1, Ordering::Relaxed);
        } else {
            log::error!(
                "Attempted to increment warning counter for {:?} which is not in the map. \
                 This indicates a bug in ProcessingStats initialization.",
                warning
            );
            // Don't panic - log and continue to avoid crashing the application
        }
    }

    /// Increment an info counter.
    ///
    /// # Safety
    /// This should never panic if `ProcessingStats` is properly initialized via `new()`.
    /// All info types are initialized in the constructor. If a panic occurs, it indicates
    /// a bug in initialization or a missing enum variant.
    pub fn increment_info(&self, info_type: InfoType) {
        if let Some(counter) = self.info.get(&info_type) {
            counter.fetch_add(1, Ordering::Relaxed);
        } else {
            log::error!(
                "Attempted to increment info counter for {:?} which is not in the map. \
                 This indicates a bug in ProcessingStats initialization.",
                info_type
            );
            // Don't panic - log and continue to avoid crashing the application
        }
    }

    /// Get the count for an error type.
    ///
    /// Returns 0 if the error type is not in the map (should never happen if properly initialized).
    pub fn get_error_count(&self, error: ErrorType) -> usize {
        self.errors
            .get(&error)
            .map(|c| c.load(Ordering::SeqCst))
            .unwrap_or_else(|| {
                log::warn!(
                    "Error type {:?} not found in stats map, returning 0. \
                     This indicates a bug in ProcessingStats initialization.",
                    error
                );
                0
            })
    }

    /// Get the count for a warning type.
    ///
    /// Returns 0 if the warning type is not in the map (should never happen if properly initialized).
    pub fn get_warning_count(&self, warning: WarningType) -> usize {
        self.warnings
            .get(&warning)
            .map(|c| c.load(Ordering::SeqCst))
            .unwrap_or_else(|| {
                log::warn!(
                    "Warning type {:?} not found in stats map, returning 0. \
                     This indicates a bug in ProcessingStats initialization.",
                    warning
                );
                0
            })
    }

    /// Get the count for an info type.
    ///
    /// Returns 0 if the info type is not in the map (should never happen if properly initialized).
    pub fn get_info_count(&self, info_type: InfoType) -> usize {
        self.info
            .get(&info_type)
            .map(|c| c.load(Ordering::SeqCst))
            .unwrap_or_else(|| {
                log::warn!(
                    "Info type {:?} not found in stats map, returning 0. \
                     This indicates a bug in ProcessingStats initialization.",
                    info_type
                );
                0
            })
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
