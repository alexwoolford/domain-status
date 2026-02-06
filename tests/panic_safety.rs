//! Tests to ensure no panics occur in normal operation
//!
//! These tests verify that the public API handles edge cases gracefully
//! without panicking. The regex pattern and CSS selector validation happens
//! at program startup (tested at unit level), so these integration tests
//! focus on the public API behavior.
//!
//! Note: Detailed panic safety for internal modules (parse::analytics,
//! parse::social, etc.) is tested at the unit level within those modules.

#![allow(clippy::field_reassign_with_default)]

use domain_status::Config;

#[test]
fn test_config_validation_does_not_panic() {
    // Test that config validation handles invalid values gracefully
    let mut config = Config::default();

    // Test zero values
    config.max_concurrency = 0;
    let result = config.validate();
    assert!(
        result.is_err(),
        "Zero max_concurrency should fail validation"
    );

    // Test boundary values
    config = Config::default();
    config.max_concurrency = 1000;
    let result = config.validate();
    assert!(
        result.is_err(),
        "Excessive concurrency should fail validation"
    );

    // Test percentage out of range
    config = Config::default();
    config.fail_on_pct_threshold = 101;
    let result = config.validate();
    assert!(result.is_err(), "Invalid percentage should fail validation");
}

#[test]
fn test_config_default_values_are_valid() {
    // Test that default config is valid
    let config = Config::default();
    let result = config.validate();
    assert!(result.is_ok(), "Default config should be valid");
}

#[test]
fn test_config_validation_with_extreme_values() {
    // Test that extreme values don't cause panics
    let mut config = Config::default();

    config.max_concurrency = usize::MAX;
    let _result = config.validate(); // May fail or succeed, but shouldn't panic

    config = Config::default();
    config.timeout_seconds = u64::MAX;
    let _result = config.validate(); // May fail or succeed, but shouldn't panic

    config = Config::default();
    config.adaptive_error_threshold = f64::MAX;
    let _result = config.validate(); // Should fail, but shouldn't panic
}

#[test]
fn test_config_fail_on_enum_variants() {
    // Test that all FailOn variants work without panic
    use domain_status::FailOn;

    let mut config = Config::default();

    config.fail_on = FailOn::Never;
    assert!(config.validate().is_ok());

    config.fail_on = FailOn::AnyFailure;
    assert!(config.validate().is_ok());

    config.fail_on = FailOn::PctGreaterThan;
    assert!(config.validate().is_ok());

    config.fail_on = FailOn::ErrorsOnly;
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_handles_empty_paths_gracefully() {
    // Test that empty file paths don't cause panics during validation
    use std::path::PathBuf;

    let mut config = Config::default();
    config.file = PathBuf::from("");
    let result = config.validate();
    // Validation might pass or fail, but shouldn't panic
    let _ = result;
}

#[test]
fn test_config_handles_invalid_user_agent() {
    // Test that invalid user agent values don't cause panics
    let mut config = Config::default();

    config.user_agent = String::from("");
    let _result = config.validate(); // May fail, but shouldn't panic

    config.user_agent = "x".repeat(10000);
    let _result = config.validate(); // May fail, but shouldn't panic

    config.user_agent = String::from("\0\0\0");
    let _result = config.validate(); // May fail, but shouldn't panic
}
