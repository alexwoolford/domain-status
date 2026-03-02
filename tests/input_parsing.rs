//! Input parsing behavior (comments, blank lines) is exercised by the real code path
//! in `src/run/mod.rs::test_run_scan_file_with_comments`, which runs `run_scan` with
//! a file containing "# comment\nhttps://example.com\n" and asserts one URL is attempted.
//!
//! This file exists to document where input parsing is tested; no duplicate
//! reimplementation of the parsing logic is tested here.
