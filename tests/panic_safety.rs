//! Integration tests to ensure Config validation does not panic.
//!
//! Detailed validation rules are tested in `src/config/types.rs`. Here we only check that
//! the public API handles invalid or extreme inputs without panicking.

#![allow(clippy::field_reassign_with_default)]

use domain_status::Config;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;

#[test]
fn test_config_default_values_are_valid() {
    let config = Config::default();
    assert!(config.validate().is_ok(), "Default config should be valid");
}

#[test]
fn test_config_fail_on_enum_variants_all_valid() {
    use domain_status::FailOn;

    for variant in [FailOn::Never, FailOn::AnyFailure, FailOn::PctGreaterThan] {
        let mut config = Config::default();
        config.fail_on = variant.clone();
        assert!(
            config.validate().is_ok(),
            "Config with fail_on {:?} should validate",
            variant
        );
    }
}

#[test]
fn test_config_validation_does_not_panic_on_extreme_or_invalid_inputs() {
    let mut config = Config::default();
    config.max_concurrency = usize::MAX;
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| config.validate()))
        .expect("validate should not panic");
    assert!(
        result.is_err(),
        "extreme max_concurrency should be rejected"
    );
    assert_eq!(
        result.expect_err("validation error").field,
        "max_concurrency"
    );

    config = Config::default();
    config.max_concurrency = 0;
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| config.validate()))
        .expect("validate should not panic");
    assert!(result.is_err(), "zero max_concurrency should fail");
    assert_eq!(
        result.expect_err("validation error").field,
        "max_concurrency"
    );

    config = Config::default();
    config.timeout_seconds = u64::MAX;
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| config.validate()))
        .expect("validate should not panic");
    assert!(
        result.is_ok(),
        "very large timeout is allowed but must not panic"
    );

    config = Config::default();
    config.timeout_seconds = 0;
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| config.validate()))
        .expect("validate should not panic");
    assert!(result.is_err(), "zero timeout_seconds should fail");
    assert_eq!(
        result.expect_err("validation error").field,
        "timeout_seconds"
    );

    config = Config::default();
    config.adaptive_error_threshold = f64::MAX;
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| config.validate()))
        .expect("validate should not panic");
    assert!(result.is_err(), "out-of-range threshold should fail");
    assert_eq!(
        result.expect_err("validation error").field,
        "adaptive_error_threshold"
    );

    config = Config::default();
    config.file = PathBuf::from("");
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| config.validate()))
        .expect("validate should not panic");
    assert!(
        result.is_ok(),
        "empty file path is not validated today, but validation must stay panic-free"
    );

    config = Config::default();
    config.user_agent = String::new();
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| config.validate()))
        .expect("validate should not panic");
    assert!(result.is_err(), "empty user_agent should fail");
    assert_eq!(result.expect_err("validation error").field, "user_agent");

    config = Config::default();
    config.user_agent = "x".repeat(10000);
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| config.validate()))
        .expect("validate should not panic");
    assert!(result.is_ok(), "long user_agent should remain valid");
}
