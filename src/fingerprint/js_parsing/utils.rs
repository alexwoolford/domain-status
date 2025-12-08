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
