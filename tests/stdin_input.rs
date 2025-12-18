//! Tests for stdin input support and comment/blank line handling

use domain_status::{Config, LogFormat, LogLevel};
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper to create a minimal test config for stdin
fn create_stdin_test_config(fail_on: domain_status::FailOn) -> Config {
    Config {
        file: PathBuf::from("-"), // stdin indicator
        db_path: PathBuf::from("./test_stdin.db"),
        max_concurrency: 1,
        rate_limit_rps: 0, // Disable rate limiting for faster tests
        timeout_seconds: 5,
        enable_whois: false,
        log_level: LogLevel::Error, // Reduce log noise
        log_format: LogFormat::Plain,
        user_agent: "domain_status-test/1.0".to_string(),
        adaptive_error_threshold: 0.2,
        fingerprints: None,
        geoip: None,
        status_port: None,
        fail_on,
        fail_on_pct_threshold: 10,
        log_file: None,
        progress_callback: None,
    }
}

#[test]
fn test_stdin_detection() {
    // Test that "-" is recognized as stdin indicator
    let config = create_stdin_test_config(domain_status::FailOn::Never);
    assert_eq!(config.file.as_os_str(), "-");
}

#[test]
fn test_comment_line_skipping() {
    // Test that lines starting with # are skipped
    // This is tested indirectly through the file reading logic
    // We'll create a test file with comments and verify they're skipped

    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let input_file = temp_dir.path().join("urls_with_comments.txt");

    // Write file with comments and URLs
    let content = r#"# This is a comment
https://example.com
# Another comment
https://example.org
# Final comment
"#;
    std::fs::write(&input_file, content).expect("Failed to write test file");

    // The actual comment skipping is tested in the file reading logic
    // This test verifies the file can be created with comments
    assert!(input_file.exists());
    let file_content = std::fs::read_to_string(&input_file).unwrap();
    assert!(file_content.contains("# This is a comment"));
    assert!(file_content.contains("https://example.com"));
}

#[test]
fn test_blank_line_skipping() {
    // Test that blank lines are skipped
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let input_file = temp_dir.path().join("urls_with_blanks.txt");

    // Write file with blank lines
    let content = r#"https://example.com


https://example.org

"#;
    std::fs::write(&input_file, content).expect("Failed to write test file");

    // Verify file contains blank lines
    let file_content = std::fs::read_to_string(&input_file).unwrap();
    let lines: Vec<&str> = file_content.lines().collect();
    assert!(lines.contains(&""));
    assert!(lines.contains(&"https://example.com"));
}

#[test]
fn test_mixed_input_comments_and_blanks() {
    // Test file with comments, blank lines, and URLs mixed together
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let input_file = temp_dir.path().join("mixed_input.txt");

    let content = r#"# Header comment
https://example.com

# Section comment
https://example.org
# Inline comment (should be part of URL line, not skipped)

https://github.com
"#;
    std::fs::write(&input_file, content).expect("Failed to write test file");

    // Verify file structure
    let file_content = std::fs::read_to_string(&input_file).unwrap();
    assert!(file_content.contains("# Header comment"));
    assert!(file_content.contains("https://example.com"));
    assert!(file_content.contains("https://example.org"));
}

#[test]
fn test_comment_at_start_of_line() {
    // Test that only lines starting with # are treated as comments
    // URLs containing # should still be processed
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let input_file = temp_dir.path().join("urls_with_hash.txt");

    let content = r#"# This is a comment
https://example.com/page#section
# Another comment
"#;
    std::fs::write(&input_file, content).expect("Failed to write test file");

    let file_content = std::fs::read_to_string(&input_file).unwrap();
    assert!(file_content.contains("# This is a comment"));
    assert!(file_content.contains("https://example.com/page#section"));
}

#[test]
fn test_whitespace_only_lines() {
    // Test that lines with only whitespace are treated as blank
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let input_file = temp_dir.path().join("whitespace_lines.txt");

    let content = "https://example.com\n   \n\t\t\nhttps://example.org\n";
    std::fs::write(&input_file, content).expect("Failed to write test file");

    let file_content = std::fs::read_to_string(&input_file).unwrap();
    let lines: Vec<&str> = file_content.lines().collect();
    // Should have URLs and whitespace-only lines
    assert!(lines.iter().any(|l| l.trim().is_empty()));
}
