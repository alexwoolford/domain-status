//! Integration tests for Config validation error messages.
//!
//! These tests verify that validation returns Err with a descriptive message and consistent
//! structure. Field-by-field validation behavior is covered by unit tests in `src/config/types.rs`.

#![allow(clippy::field_reassign_with_default)]

use domain_status::Config;

#[test]
fn test_validation_returns_descriptive_error() {
    // One integration-level check: invalid config returns Err with non-empty field and message
    let mut config = Config::default();
    config.max_concurrency = 0;
    let result = config.validate();
    assert!(
        result.is_err(),
        "Zero max_concurrency should fail validation"
    );
    let e = result.unwrap_err();
    assert_eq!(e.field, "max_concurrency");
    assert!(
        e.message.contains("greater than 0") || e.message.contains("0"),
        "Error should mention valid range or value"
    );
}

#[test]
fn test_validation_errors_have_consistent_structure() {
    // Errors should always specify field and message (actionable for users)
    let mut config = Config::default();
    config.timeout_seconds = 0;
    let err = config.validate().unwrap_err();
    assert!(!err.field.is_empty(), "Error should specify field");
    assert!(!err.message.is_empty(), "Error should have message");
}
