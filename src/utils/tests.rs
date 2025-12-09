// Utils module tests.

use anyhow::Error;

use crate::utils::retry::is_retriable_error;

// Note: Testing is_retriable_error with actual reqwest::Error instances is complex
// because reqwest::Error doesn't expose a simple constructor. These tests verify
// the logic for non-reqwest errors. For comprehensive testing of reqwest errors,
// integration tests with a mock HTTP server (e.g., httptest) would be better.

#[test]
fn test_is_retriable_error_url_parse() {
    // URL parse errors should NOT be retriable
    let parse_error = url::ParseError::EmptyHost;
    let error = Error::from(parse_error);
    assert!(!is_retriable_error(&error));
}

// Note: test_is_retriable_error_database is tested in src/utils/retry.rs
// This test was removed to avoid duplication
