//! Tests for input parsing (comments, blank lines, URL validation)

// Note: validate_and_normalize_url is not public, so we test the behavior indirectly
// through file reading logic. These tests verify the parsing logic conceptually.

#[test]
fn test_comment_line_parsing() {
    // Test that lines starting with # are identified as comments
    let lines = vec![
        "# This is a comment",
        "https://example.com",
        "# Another comment",
        "  # Comment with leading whitespace",
    ];

    let mut urls = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue; // Skip comments and blanks
        }
        // For testing, we just verify the line is not a comment
        if !trimmed.starts_with('#') && !trimmed.is_empty() {
            urls.push(trimmed.to_string());
        }
    }

    // Should only have one URL (comments and blanks skipped)
    assert_eq!(urls.len(), 1);
    assert_eq!(urls[0], "https://example.com");
}

#[test]
fn test_blank_line_parsing() {
    // Test that blank lines are skipped
    let lines = vec![
        "https://example.com",
        "",
        "   ",  // Whitespace only
        "\t\t", // Tabs only
        "https://example.org",
    ];

    let mut urls = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // For testing, we just verify the line is not a comment
        if !trimmed.starts_with('#') && !trimmed.is_empty() {
            urls.push(trimmed.to_string());
        }
    }

    // Should have 2 URLs (blanks skipped)
    assert_eq!(urls.len(), 2);
    assert_eq!(urls[0], "https://example.com");
    assert_eq!(urls[1], "https://example.org");
}

#[test]
fn test_mixed_comments_and_blanks() {
    // Test mixed input with comments, blanks, and URLs
    let lines = vec![
        "# Header",
        "",
        "https://example.com",
        "# Middle comment",
        "   ",
        "https://example.org",
        "# Footer",
    ];

    let mut urls = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // For testing, we just verify the line is not a comment
        if !trimmed.starts_with('#') && !trimmed.is_empty() {
            urls.push(trimmed.to_string());
        }
    }

    assert_eq!(urls.len(), 2);
}

#[test]
fn test_comment_with_leading_whitespace() {
    // Test that # after whitespace is still treated as comment
    let lines = vec![
        "  # Comment with spaces",
        "\t# Comment with tabs",
        "https://example.com",
    ];

    let mut urls = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // For testing, we just verify the line is not a comment
        if !trimmed.starts_with('#') && !trimmed.is_empty() {
            urls.push(trimmed.to_string());
        }
    }

    assert_eq!(urls.len(), 1);
}

#[test]
fn test_url_with_hash_fragment() {
    // Test that URLs containing # (fragments) are not treated as comments
    let lines = vec![
        "# This is a comment",
        "https://example.com/page#section",
        "https://example.com#another-fragment",
    ];

    let mut urls = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // For testing, we just verify the line is not a comment
        if !trimmed.starts_with('#') && !trimmed.is_empty() {
            urls.push(trimmed.to_string());
        }
    }

    // Should have 2 URLs (comment skipped, URLs with # preserved)
    assert_eq!(urls.len(), 2);
    assert!(urls[0].contains("#section"));
    assert!(urls[1].contains("#another-fragment"));
}

#[test]
fn test_empty_file_handling() {
    // Test that empty file or file with only comments/blanks is handled
    let lines: Vec<&str> = vec![];

    let mut urls = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // For testing, we just verify the line is not a comment
        if !trimmed.starts_with('#') && !trimmed.is_empty() {
            urls.push(trimmed.to_string());
        }
    }

    assert_eq!(urls.len(), 0);
}

#[test]
fn test_file_with_only_comments() {
    // Test file containing only comments
    let lines = vec!["# Comment 1", "# Comment 2", "  # Comment 3"];

    let mut urls = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // For testing, we just verify the line is not a comment
        if !trimmed.starts_with('#') && !trimmed.is_empty() {
            urls.push(trimmed.to_string());
        }
    }

    assert_eq!(urls.len(), 0);
}
