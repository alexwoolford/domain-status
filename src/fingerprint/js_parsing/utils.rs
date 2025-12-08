//! JavaScript pattern parsing utilities (does NOT execute JavaScript).
//!
//! This module provides utility functions for parsing JavaScript patterns from HTML.
//! These functions are used for pattern matching only - JavaScript is NOT executed.

/// Strips JavaScript comments and string literals from code to avoid false positives.
///
/// **Note:** This function is only used in tests. Production code does NOT execute
/// JavaScript - it only matches patterns against inline script content from HTML.
///
/// Handles:
/// - Single-line comments (// ...)
/// - Multi-line comments (/* ... */)
/// - Single-quoted strings ('...')
/// - Double-quoted strings ("...")
/// - Template literals (`...`)
#[cfg(test)]
pub fn strip_js_comments_and_strings(code: &str) -> String {
    let mut result = String::with_capacity(code.len());
    let mut chars = code.chars().peekable();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_template_literal = false;
    let mut in_single_line_comment = false;
    let mut in_multi_line_comment = false;
    let mut prev_char = '\0';

    while let Some(ch) = chars.next() {
        let next_char = chars.peek().copied().unwrap_or('\0');

        // Handle escaping in strings
        if (in_single_quote || in_double_quote || in_template_literal) && ch == '\\' {
            // Skip escaped character
            result.push(ch);
            if let Some(escaped) = chars.next() {
                result.push(escaped);
            }
            prev_char = ch;
            continue;
        }

        // Check for string/template literal start/end
        if !in_single_line_comment && !in_multi_line_comment {
            if ch == '\'' && !in_double_quote && !in_template_literal {
                in_single_quote = !in_single_quote;
                result.push(' '); // Replace with space to preserve positions
                prev_char = ch;
                continue;
            }
            if ch == '"' && !in_single_quote && !in_template_literal {
                in_double_quote = !in_double_quote;
                result.push(' ');
                prev_char = ch;
                continue;
            }
            if ch == '`' && !in_single_quote && !in_double_quote {
                in_template_literal = !in_template_literal;
                result.push(' ');
                prev_char = ch;
                continue;
            }
        }

        // If we're in a string, skip it
        if in_single_quote || in_double_quote || in_template_literal {
            result.push(' ');
            prev_char = ch;
            continue;
        }

        // Check for comment start
        if !in_single_line_comment && !in_multi_line_comment {
            if ch == '/' && next_char == '/' {
                in_single_line_comment = true;
                result.push(' ');
                chars.next(); // Skip the second '/'
                prev_char = ch;
                continue;
            }
            if ch == '/' && next_char == '*' {
                in_multi_line_comment = true;
                result.push(' ');
                chars.next(); // Skip the '*'
                prev_char = ch;
                continue;
            }
        }

        // Check for comment end
        if in_multi_line_comment && prev_char == '*' && ch == '/' {
            in_multi_line_comment = false;
            result.push(' ');
            prev_char = ch;
            continue;
        }
        if in_single_line_comment && ch == '\n' {
            in_single_line_comment = false;
            result.push('\n');
            prev_char = ch;
            continue;
        }

        // If we're in a comment, skip it
        if in_single_line_comment || in_multi_line_comment {
            result.push(' ');
            prev_char = ch;
            continue;
        }

        // Regular code character
        result.push(ch);
        prev_char = ch;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_js_comments_and_strings_single_line_comment() {
        let code = "var x = 1; // This is a comment\nvar y = 2;";
        let result = strip_js_comments_and_strings(code);
        // Comment should be replaced with spaces, newline preserved
        assert!(result.contains("var x = 1"));
        assert!(result.contains("var y = 2"));
        assert!(result.contains('\n'));
        assert!(!result.contains("This is a comment"));
    }

    #[test]
    fn test_strip_js_comments_and_strings_multi_line_comment() {
        let code = "var x = 1; /* This is a\nmulti-line comment */ var y = 2;";
        let result = strip_js_comments_and_strings(code);
        // Multi-line comment should be replaced with spaces
        assert!(result.contains("var x = 1"));
        assert!(result.contains("var y = 2"));
        assert!(!result.contains("This is a"));
        assert!(!result.contains("multi-line comment"));
    }

    #[test]
    fn test_strip_js_comments_and_strings_double_quoted_string() {
        let code = r#"var x = "hello world"; var y = 2;"#;
        let result = strip_js_comments_and_strings(code);
        // String content should be replaced with spaces
        assert!(result.contains("var x ="));
        assert!(result.contains("var y = 2"));
        assert!(!result.contains("hello world"));
    }

    #[test]
    fn test_strip_js_comments_and_strings_single_quoted_string() {
        let code = "var x = 'hello world'; var y = 2;";
        let result = strip_js_comments_and_strings(code);
        // String content should be replaced with spaces
        assert!(result.contains("var x ="));
        assert!(result.contains("var y = 2"));
        assert!(!result.contains("hello world"));
    }

    #[test]
    fn test_strip_js_comments_and_strings_template_literal() {
        let code = "var x = `hello ${world}`; var y = 2;";
        let result = strip_js_comments_and_strings(code);
        // Template literal content should be replaced with spaces
        assert!(result.contains("var x ="));
        assert!(result.contains("var y = 2"));
        assert!(!result.contains("hello"));
    }

    #[test]
    fn test_strip_js_comments_and_strings_escaped_quotes() {
        let code = r#"var x = "hello \"world\""; var y = 2;"#;
        let result = strip_js_comments_and_strings(code);
        // Escaped quotes should be handled (backslash and quote preserved, content replaced)
        assert!(result.contains("var x ="));
        assert!(result.contains("var y = 2"));
        assert!(!result.contains("hello"));
    }

    #[test]
    fn test_strip_js_comments_and_strings_nested_strings() {
        let code = r#"var x = "outer 'inner' string"; var y = 2;"#;
        let result = strip_js_comments_and_strings(code);
        // Nested quotes should be treated as part of outer string
        assert!(result.contains("var x ="));
        assert!(result.contains("var y = 2"));
        assert!(!result.contains("outer"));
    }

    #[test]
    fn test_strip_js_comments_and_strings_comment_in_string() {
        let code = r#"var x = "string with // comment"; var y = 2;"#;
        let result = strip_js_comments_and_strings(code);
        // Comment inside string should be part of string (not stripped separately)
        assert!(result.contains("var x ="));
        assert!(result.contains("var y = 2"));
        assert!(!result.contains("comment"));
    }

    #[test]
    fn test_strip_js_comments_and_strings_string_in_comment() {
        let code = r#"var x = 1; // comment with "string"
var y = 2;"#;
        let result = strip_js_comments_and_strings(code);
        // String in comment should be stripped with comment, newline ends comment
        assert!(result.contains("var x = 1"));
        assert!(result.contains("var y = 2"));
        assert!(!result.contains("comment"));
        assert!(!result.contains("string"));
    }

    #[test]
    fn test_strip_js_comments_and_strings_multiple_strings() {
        let code = r#"var x = "first"; var y = 'second'; var z = `third`;"#;
        let result = strip_js_comments_and_strings(code);
        // All strings should be stripped
        assert!(result.contains("var x ="));
        assert!(result.contains("var y ="));
        assert!(result.contains("var z ="));
        assert!(!result.contains("first"));
        assert!(!result.contains("second"));
        assert!(!result.contains("third"));
    }

    #[test]
    fn test_strip_js_comments_and_strings_unclosed_string() {
        let code = r#"var x = "unclosed string; var y = 2;"#;
        let result = strip_js_comments_and_strings(code);
        // Should handle unclosed string gracefully (treat as string to end)
        assert!(result.contains("var x ="));
    }

    #[test]
    fn test_strip_js_comments_and_strings_unclosed_comment() {
        let code = "var x = 1; /* unclosed comment; var y = 2;";
        let result = strip_js_comments_and_strings(code);
        // Should handle unclosed comment gracefully (treat as comment to end)
        assert!(result.contains("var x = 1"));
    }

    #[test]
    fn test_strip_js_comments_and_strings_regex_like_pattern() {
        // Test that regex-like patterns (e.g., /pattern/) are not confused with comments
        let code = "var regex = /test/; var y = 2;";
        let result = strip_js_comments_and_strings(code);
        // Note: This function doesn't handle regex literals specially, so /test/ might be partially stripped
        // This is acceptable for the use case (pattern matching, not full parsing)
        assert!(result.contains("var regex"));
    }

    #[test]
    fn test_strip_js_comments_and_strings_empty_code() {
        let code = "";
        let result = strip_js_comments_and_strings(code);
        assert_eq!(result, "");
    }

    #[test]
    fn test_strip_js_comments_and_strings_only_comments() {
        let code = "// Only comment\n/* Another comment */";
        let result = strip_js_comments_and_strings(code);
        // Comments should be replaced with spaces, newline preserved
        assert!(result.contains('\n'));
        assert!(!result.contains("Only comment"));
        assert!(!result.contains("Another comment"));
    }

    #[test]
    fn test_strip_js_comments_and_strings_only_strings() {
        let code = r#""string1" 'string2' `string3`"#;
        let result = strip_js_comments_and_strings(code);
        // Strings should be replaced with spaces
        assert!(!result.contains("string1"));
        assert!(!result.contains("string2"));
        assert!(!result.contains("string3"));
    }

    #[test]
    fn test_strip_js_comments_and_strings_complex_nested() {
        let code = r#"var x = "outer /* not a comment */ string"; // comment with "string"
        var y = 'inner // not a comment';"#;
        let result = strip_js_comments_and_strings(code);
        // Should strip strings and comments correctly
        assert!(result.contains("var x ="));
        assert!(result.contains("var y ="));
    }

    #[test]
    fn test_strip_js_comments_and_strings_escaped_backslash() {
        let code = r#"var x = "path\\to\\file"; var y = 2;"#;
        let result = strip_js_comments_and_strings(code);
        // Escaped backslashes should be handled correctly
        assert!(result.contains("var x ="));
        assert!(result.contains("var y = 2"));
    }

    #[test]
    fn test_strip_js_comments_and_strings_template_literal_with_expression() {
        let code = "var x = `hello ${name}`; var y = 2;";
        let result = strip_js_comments_and_strings(code);
        // Template literal should be stripped
        assert!(result.contains("var x ="));
        assert!(result.contains("var y = 2"));
        assert!(!result.contains("hello"));
    }

    #[test]
    fn test_strip_js_comments_and_strings_multiline_string() {
        let code = r#"var x = "line1
line2
line3"; var y = 2;"#;
        let result = strip_js_comments_and_strings(code);
        // Multi-line string should be stripped
        assert!(result.contains("var x ="));
        assert!(result.contains("var y = 2"));
    }
}
