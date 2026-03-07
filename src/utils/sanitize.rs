//! Utilities for sanitizing error messages and user input.
//!
//! Removes control characters and potentially problematic content
//! from error messages before storing them in the database.
//!
//! Also provides error message truncation to prevent database bloat.

/// Sanitizes an error message by removing control characters.
///
/// Control characters (0x00-0x1F, except newline/tab/carriage return) can cause
/// issues when stored in databases or displayed in logs. This function removes
/// them while preserving readability.
///
/// # Arguments
///
/// * `message` - The error message to sanitize
///
/// # Returns
///
/// A sanitized version of the message with control characters removed.
pub fn sanitize_error_message(message: &str) -> String {
    message
        .chars()
        .filter(|c| {
            // Allow printable ASCII, newline, tab, carriage return
            // Remove other control characters (0x00-0x1F except \n, \t, \r)
            let code = *c as u32;
            code >= 0x20 // Printable ASCII starts at 0x20 (space)
                || code == 0x09 // Tab
                || code == 0x0A // Newline
                || code == 0x0D // Carriage return
                || code > 0x7F // Allow non-ASCII (UTF-8)
        })
        .collect()
}

fn truncate_at_char_boundary(value: &str, max_len: usize) -> &str {
    if value.len() <= max_len {
        return value;
    }

    let mut end = max_len;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// Truncates a string to a maximum byte length without splitting UTF-8 code points.
pub fn truncate_utf8(value: &str, max_len: usize) -> String {
    truncate_at_char_boundary(value, max_len).to_string()
}

/// Truncates a string and appends a suffix, preserving valid UTF-8 boundaries.
pub fn truncate_utf8_with_suffix(value: &str, max_len: usize, suffix: &str) -> String {
    if value.len() <= max_len {
        return value.to_string();
    }

    if max_len == 0 {
        return String::new();
    }

    if suffix.len() >= max_len {
        return truncate_utf8(suffix, max_len);
    }

    let prefix = truncate_at_char_boundary(value, max_len.saturating_sub(suffix.len()));
    format!("{prefix}{suffix}")
}

/// Sanitizes and truncates an error message to a maximum length.
///
/// This function:
/// 1. Sanitizes the message by removing control characters
/// 2. Truncates to `MAX_ERROR_MESSAGE_LENGTH` if necessary
/// 3. Appends truncation indicator if the message was truncated
///
/// # Arguments
///
/// * `message` - The error message to sanitize and truncate
///
/// # Returns
///
/// A sanitized and truncated version of the message.
pub fn sanitize_and_truncate_error_message(message: &str) -> String {
    let sanitized = sanitize_error_message(message);

    if sanitized.len() > crate::config::MAX_ERROR_MESSAGE_LENGTH {
        let suffix = format!(
            "... (truncated, original length: {} chars)",
            sanitized.chars().count()
        );
        truncate_utf8_with_suffix(&sanitized, crate::config::MAX_ERROR_MESSAGE_LENGTH, &suffix)
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_error_message_removes_control_chars() {
        let input = "Error\x00message\x01with\x02control\x03chars";
        let output = sanitize_error_message(input);
        assert_eq!(output, "Errormessagewithcontrolchars");
    }

    #[test]
    fn test_sanitize_error_message_preserves_newlines() {
        let input = "Error\nmessage\nwith\nnewlines";
        let output = sanitize_error_message(input);
        assert_eq!(output, "Error\nmessage\nwith\nnewlines");
    }

    #[test]
    fn test_sanitize_error_message_preserves_tabs() {
        let input = "Error\tmessage\twith\ttabs";
        let output = sanitize_error_message(input);
        assert_eq!(output, "Error\tmessage\twith\ttabs");
    }

    #[test]
    fn test_sanitize_error_message_preserves_unicode() {
        let input = "Error message with unicode: 测试 🚀";
        let output = sanitize_error_message(input);
        assert_eq!(output, "Error message with unicode: 测试 🚀");
    }

    #[test]
    fn test_sanitize_error_message_empty_string() {
        let input = "";
        let output = sanitize_error_message(input);
        assert_eq!(output, "");
    }

    #[test]
    fn test_sanitize_error_message_normal_text() {
        let input = "Normal error message without control characters";
        let output = sanitize_error_message(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_sanitize_error_message_preserves_carriage_return() {
        let input = "Error\rmessage\rwith\rcarriage\rreturns";
        let output = sanitize_error_message(input);
        assert_eq!(output, "Error\rmessage\rwith\rcarriage\rreturns");
    }

    #[test]
    fn test_sanitize_error_message_mixed_control_chars() {
        let input = "Error\x00\nmessage\x01\twith\x02mixed\x03chars";
        let output = sanitize_error_message(input);
        // Should preserve \n and \t, remove \x00, \x01, \x02, \x03
        assert_eq!(output, "Error\nmessage\twithmixedchars");
    }

    #[test]
    fn test_sanitize_error_message_all_control_chars() {
        // Test all control characters 0x00-0x1F except \t, \n, \r
        let mut input = String::new();
        for i in 0..=0x1F {
            if i != 0x09 && i != 0x0A && i != 0x0D {
                input.push(char::from_u32(i).unwrap());
            }
        }
        let output = sanitize_error_message(&input);
        assert_eq!(
            output, "",
            "All control chars except \\t, \\n, \\r should be removed"
        );
    }

    #[test]
    fn test_sanitize_error_message_unicode_control_chars() {
        // Test that non-ASCII characters (including Unicode) are preserved
        let input = "Error with unicode: 测试 🚀 \u{200B}"; // \u{200B} is zero-width space
        let output = sanitize_error_message(input);
        // Unicode characters > 0x7F should be preserved
        assert!(output.contains("测试"));
        assert!(output.contains("🚀"));
    }

    #[test]
    fn test_sanitize_and_truncate_error_message_short() {
        let input = "Short error message";
        let output = sanitize_and_truncate_error_message(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_sanitize_and_truncate_error_message_long() {
        // Create a message longer than MAX_ERROR_MESSAGE_LENGTH
        let long_message = "A".repeat(crate::config::MAX_ERROR_MESSAGE_LENGTH + 100);
        let output = sanitize_and_truncate_error_message(&long_message);

        // Should be truncated
        assert!(output.len() < long_message.len());
        assert!(output.contains("... (truncated"));
        assert!(output.contains("original length:"));
    }

    #[test]
    fn test_sanitize_and_truncate_error_message_exact_length() {
        // Test message exactly at MAX_ERROR_MESSAGE_LENGTH
        let exact_message = "A".repeat(crate::config::MAX_ERROR_MESSAGE_LENGTH);
        let output = sanitize_and_truncate_error_message(&exact_message);

        // Should not be truncated (exactly at limit)
        assert_eq!(output, exact_message);
    }

    #[test]
    fn test_sanitize_and_truncate_error_message_one_over_limit() {
        // Test message one character over limit
        let over_limit = "A".repeat(crate::config::MAX_ERROR_MESSAGE_LENGTH + 1);
        let output = sanitize_and_truncate_error_message(&over_limit);

        // Should be truncated
        assert!(output.len() < over_limit.len());
        assert!(output.contains("... (truncated"));
    }

    #[test]
    fn test_sanitize_and_truncate_error_message_with_control_chars() {
        // Test that sanitization happens before truncation
        let input = format!(
            "{}\x00\x01\x02",
            "A".repeat(crate::config::MAX_ERROR_MESSAGE_LENGTH + 50)
        );
        let output = sanitize_and_truncate_error_message(&input);

        // Should have control chars removed AND be truncated
        assert!(!output.contains('\x00'));
        assert!(!output.contains('\x01'));
        assert!(!output.contains('\x02'));
        assert!(output.contains("... (truncated"));
    }

    #[test]
    fn test_sanitize_error_message_boundary_chars() {
        // Test boundary characters: 0x1F (last control char), 0x20 (first printable)
        let input = "Before\x1FAfter\x20Space";
        let output = sanitize_error_message(input);
        // 0x1F should be removed, 0x20 (space) should be preserved
        assert_eq!(output, "BeforeAfter Space");
    }

    #[test]
    fn test_sanitize_error_message_very_long_unicode() {
        // Test with very long Unicode string
        let input = "测试".repeat(1000);
        let output = sanitize_error_message(&input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_sanitize_and_truncate_error_message_unicode_boundary() {
        // Test truncation at Unicode character boundary
        // This is critical - truncating in the middle of a multi-byte char could cause issues
        let unicode_text = "测试🚀";
        let long_message = format!(
            "{}{}",
            unicode_text.repeat(1000),
            "A".repeat(crate::config::MAX_ERROR_MESSAGE_LENGTH)
        );
        let output = sanitize_and_truncate_error_message(&long_message);

        // Should be truncated and should not panic
        assert!(output.len() < long_message.len());
        assert!(output.contains("... (truncated"));
        assert!(std::str::from_utf8(output.as_bytes()).is_ok());
    }

    #[test]
    fn test_sanitize_and_truncate_error_message_very_small_limit() {
        // Test with very small MAX_ERROR_MESSAGE_LENGTH (edge case)
        // If MAX_ERROR_MESSAGE_LENGTH < 50, truncate_len could be 0 or negative
        // This tests the saturating_sub and min logic
        let message = "A".repeat(100);
        let output = sanitize_and_truncate_error_message(&message);

        // Should handle gracefully even if truncate_len calculation is edge case
        // The saturating_sub(50) and min(sanitized.len()) should prevent issues
        assert!(output.len() <= message.len() + 50); // Account for truncation message
    }

    #[test]
    fn test_sanitize_and_truncate_error_message_control_chars_affect_length() {
        // Test that removing control chars before truncation affects final length
        // This is important - if control chars are removed, the message might not need truncation
        let base_message = "A".repeat(crate::config::MAX_ERROR_MESSAGE_LENGTH - 10);
        let message_with_control = format!("{}\x00\x01\x02\x03\x04\x05", base_message);

        let output = sanitize_and_truncate_error_message(&message_with_control);

        // Control chars should be removed, so message might not need truncation
        // (depending on MAX_ERROR_MESSAGE_LENGTH)
        assert!(!output.contains('\x00'));
        // Should not be truncated if removing control chars makes it short enough
        if base_message.len() <= crate::config::MAX_ERROR_MESSAGE_LENGTH {
            assert!(!output.contains("... (truncated"));
        }
    }

    #[test]
    fn test_truncate_utf8_preserves_code_point_boundaries() {
        let value = "prefix-测试🚀-suffix";
        let truncated = truncate_utf8(value, 10);
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
        assert!(value.starts_with(&truncated));
    }

    #[test]
    fn test_truncate_utf8_with_suffix_preserves_code_point_boundaries() {
        let value = "测试🚀测试🚀测试🚀";
        let truncated = truncate_utf8_with_suffix(value, 18, "...(cut)");
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
        assert!(truncated.ends_with("...(cut)"));
    }
}
