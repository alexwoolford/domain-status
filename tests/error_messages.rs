//! Tests to ensure error messages are actionable and consistent
//!
//! These tests verify that error messages provide clear guidance on how to
//! resolve issues, including expected formats and actionable steps.
//!
//! Note: These integration tests focus on the public API (Config validation).
//! Internal module error messages are tested at the unit level.

use domain_status::Config;

#[test]
fn test_config_validation_errors_are_descriptive() {
    // Test that config validation provides descriptive errors
    let mut config = Config::default();

    // Test max_concurrency validation
    config.max_concurrency = 0;
    let result = config.validate();
    assert!(result.is_err(), "Zero max_concurrency should fail validation");
    if let Err(e) = result {
        assert_eq!(e.field, "max_concurrency");
        assert!(e.message.contains("greater than 0"),
            "Error should mention valid range");
    }

    // Test timeout_seconds validation
    config = Config::default();
    config.timeout_seconds = 0;
    let result = config.validate();
    assert!(result.is_err(), "Zero timeout_seconds should fail validation");
    if let Err(e) = result {
        assert_eq!(e.field, "timeout_seconds");
        assert!(e.message.contains("greater than 0"),
            "Error should mention minimum value");
    }

    // Test rate_limit_rps validation
    config = Config::default();
    config.rate_limit_rps = 101;
    let result = config.validate();
    assert!(result.is_err(), "rate_limit_rps > 100 should fail validation");
    if let Err(e) = result {
        assert_eq!(e.field, "rate_limit_rps");
        assert!(e.message.contains("100") || e.message.contains("overwhelming"),
            "Error should mention maximum value");
    }

    // Test fail_on_pct_threshold validation
    config = Config::default();
    config.fail_on_pct_threshold = 101;
    let result = config.validate();
    assert!(result.is_err(), "fail_on_pct_threshold > 100 should fail validation");
    if let Err(e) = result {
        assert_eq!(e.field, "fail_on_pct_threshold");
        assert!(e.message.contains("between 0 and 100"),
            "Error should mention valid range");
    }

    // Test adaptive_error_threshold validation
    config = Config::default();
    config.adaptive_error_threshold = 1.5;
    let result = config.validate();
    assert!(result.is_err(), "adaptive_error_threshold > 1.0 should fail validation");
    if let Err(e) = result {
        assert_eq!(e.field, "adaptive_error_threshold");
        assert!(e.message.contains("between 0.0 and 1.0"),
            "Error should mention valid range");
    }
}

#[test]
fn test_error_messages_are_actionable() {
    // Test that config validation provides field-specific errors
    let mut config = Config::default();
    config.max_concurrency = 1001;
    let result = config.validate();
    assert!(result.is_err(), "Excessive max_concurrency should fail");
    if let Err(e) = result {
        assert!(!e.message.is_empty(), "Error message should not be empty");
        assert!(!e.field.is_empty(), "Error field should not be empty");
    }
}

#[test]
fn test_consistent_error_formatting() {
    // Test that config validation errors follow consistent format
    let mut config = Config::default();
    config.max_concurrency = 0;
    let result1 = config.validate();

    config = Config::default();
    config.timeout_seconds = 0;
    let result2 = config.validate();

    // Both errors should have the same structure
    assert!(result1.is_err() && result2.is_err());
    let err1 = result1.unwrap_err();
    let err2 = result2.unwrap_err();

    // Check consistent structure
    assert!(!err1.field.is_empty(), "Error should specify field");
    assert!(!err1.message.is_empty(), "Error should have message");
    assert!(!err2.field.is_empty(), "Error should specify field");
    assert!(!err2.message.is_empty(), "Error should have message");
}

#[test]
fn test_error_fields_are_specific() {
    // Test that errors identify the specific field that failed validation
    let mut config = Config::default();

    config.max_concurrency = 0;
    if let Err(e) = config.validate() {
        assert_eq!(e.field, "max_concurrency", "Should identify correct field");
    }

    config = Config::default();
    config.timeout_seconds = 0;
    if let Err(e) = config.validate() {
        assert_eq!(e.field, "timeout_seconds", "Should identify correct field");
    }

    config = Config::default();
    config.user_agent = "".to_string();
    if let Err(e) = config.validate() {
        assert_eq!(e.field, "user_agent", "Should identify correct field");
    }
}
