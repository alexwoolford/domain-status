//! CSS selector parsing utilities.

use scraper::Selector;

/// Parses a CSS selector with a safe fallback.
///
/// If parsing fails, logs an error and returns a selector that matches nothing
/// (`*:not(*)`). This prevents panics while allowing the code to continue.
///
/// # Arguments
///
/// * `selector_str` - The CSS selector string to parse
/// * `context` - Context description for error logging (e.g., "meta tag extraction")
///
/// # Returns
///
/// A parsed `Selector`, or a fallback selector that matches nothing if parsing fails.
pub fn parse_selector_with_fallback(selector_str: &str, context: &str) -> Selector {
    Selector::parse(selector_str).unwrap_or_else(|e| {
        log::error!(
            "Failed to parse CSS selector '{}' in {}: {}. Using fallback selector.",
            selector_str,
            context,
            e
        );
        // Fallback to a selector that won't match anything
        // Use a known-valid selector that won't match: "*:not(*)"
        Selector::parse("*:not(*)").expect(
            "Fallback selector '*:not(*)' should always parse - this is a programming error",
        )
    })
}

/// Parses a CSS selector that must succeed (for compile-time constants).
///
/// This function panics if parsing fails, which is appropriate for static selectors
/// that are compile-time constants. Use `parse_selector_with_fallback()` for
/// dynamic selectors.
///
/// # Arguments
///
/// * `selector_str` - The CSS selector string to parse
/// * `context` - Context description for error messages
///
/// # Panics
///
/// Panics if the selector cannot be parsed (indicates a programming error).
pub fn parse_selector_unsafe(selector_str: &str, context: &str) -> Selector {
    Selector::parse(selector_str).unwrap_or_else(|e| {
        panic!(
            "Failed to parse CSS selector '{}' in {}: {}. This is a programming error.",
            selector_str, context, e
        )
    })
}

