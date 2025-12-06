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
        // Truncate to MAX_ERROR_MESSAGE_LENGTH - 50 to leave room for truncation message
        // Use min to ensure we don't go out of bounds if constant is changed
        let truncate_len = crate::config::MAX_ERROR_MESSAGE_LENGTH.saturating_sub(50);
        let truncate_len = truncate_len.min(sanitized.len());
        format!(
            "{}... (truncated, original length: {} chars)",
            &sanitized[..truncate_len],
            sanitized.len()
        )
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
}
