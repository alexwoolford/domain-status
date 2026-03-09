//! Shared test fixtures and constants for integration tests.
//!
//! Uses rstest fixtures and `assert_fs` for temp dirs so tests can share setup
//! and avoid duplication. Use `#[rstest]` and inject fixtures by name.

use std::net::TcpListener;

use assert_fs::prelude::*;
use assert_fs::TempDir;
use rstest::fixture;

/// Minimal URL list content for tests that need an input file.
pub const URLS_TXT_CONTENT: &str = "https://example.com\nhttps://example.org\n";

/// Test database filename used in fixtures when a DB path is needed.
pub const TEST_DB_NAME: &str = "test_scan.db";

/// Creates a temporary directory with an optional `urls.txt` file.
///
/// Use as a fixture in rstest tests: `fn my_test(tmpdir: TempDir) { ... }`
#[fixture]
pub fn tmpdir() -> TempDir {
    let tmpdir = TempDir::new().expect("Couldn't create temp dir for tests");
    tmpdir
        .child("urls.txt")
        .write_str(URLS_TXT_CONTENT)
        .expect("Couldn't write urls.txt in fixture");
    tmpdir
}

/// Returns a temporary directory without pre-populated files.
#[fixture]
pub fn tmpdir_empty() -> TempDir {
    TempDir::new().expect("Couldn't create temp dir for tests")
}

/// Returns a port that is free at the time of the call.
///
/// Uses `TcpListener::bind("127.0.0.1:0")` and returns the assigned port.
/// The listener is dropped immediately; there is a small race before the test
/// uses the port, but in practice this is sufficient for integration tests.
#[fixture]
pub fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("Couldn't bind to get free port");
    listener
        .local_addr()
        .expect("Couldn't get local_addr")
        .port()
}
