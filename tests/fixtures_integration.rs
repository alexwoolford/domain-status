//! Integration tests that use the shared fixtures (tmpdir, `free_port`) and rstest.
//!
//! These tests demonstrate the fixture pattern and reduce setup duplication.

mod fixtures;

use assert_fs::prelude::*;
use fixtures::{free_port, tmpdir, tmpdir_empty, TEST_DB_NAME, URLS_TXT_CONTENT};
use rstest::rstest;

#[test]
fn fixture_tmpdir_has_urls_file() {
    let dir = tmpdir();
    let urls_file = dir.child("urls.txt");
    urls_file.assert(URLS_TXT_CONTENT);
}

#[test]
fn fixture_tmpdir_empty_is_empty() {
    let dir = tmpdir_empty();
    assert!(dir.path().exists());
    // No urls.txt
    assert!(!dir.child("urls.txt").path().exists());
}

#[test]
fn fixture_free_port_returns_valid_port() {
    let port = free_port();
    assert!(port > 0, "free_port should return a positive port");
}

/// Parameterized test: tmpdir path exists and urls.txt has expected content.
#[rstest]
fn fixture_tmpdir_content(tmpdir: assert_fs::TempDir) {
    assert!(tmpdir.path().exists());
    let content = std::fs::read_to_string(tmpdir.path().join("urls.txt")).expect("read urls.txt");
    assert_eq!(content, URLS_TXT_CONTENT);
}

#[test]
#[allow(clippy::const_is_empty)]
fn constants_available() {
    assert!(!URLS_TXT_CONTENT.is_empty());
    assert_eq!(TEST_DB_NAME, "test_scan.db");
}
