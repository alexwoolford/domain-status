//! Integration tests to ensure Config validation does not panic.
//!
//! Detailed validation rules are tested in `src/config/types.rs`. Here we only check that
//! the public API handles invalid or extreme inputs without panicking.

#![allow(clippy::field_reassign_with_default)]

use domain_status::Config;
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
    // Validation must return Ok or Err, never panic; assert outcome for each case.
    let mut config = Config::default();
    config.max_concurrency = usize::MAX;
    let result = config.validate();
    assert!(result.is_ok() || result.is_err());

    config = Config::default();
    config.max_concurrency = 0;
    let result = config.validate();
    assert!(result.is_err(), "zero max_concurrency should fail");
    assert_eq!(result.unwrap_err().field, "max_concurrency");

    config = Config::default();
    config.timeout_seconds = u64::MAX;
    let result = config.validate();
    assert!(result.is_ok() || result.is_err());

    config = Config::default();
    config.timeout_seconds = 0;
    let result = config.validate();
    assert!(result.is_err(), "zero timeout_seconds should fail");

    config = Config::default();
    config.adaptive_error_threshold = f64::MAX;
    let result = config.validate();
    assert!(result.is_ok() || result.is_err());

    config = Config::default();
    config.file = PathBuf::from("");
    let result = config.validate();
    assert!(result.is_ok() || result.is_err());

    config = Config::default();
    config.user_agent = String::new();
    let result = config.validate();
    assert!(result.is_err(), "empty user_agent should fail");

    config = Config::default();
    config.user_agent = "x".repeat(10000);
    let result = config.validate();
    assert!(result.is_ok() || result.is_err());
}
