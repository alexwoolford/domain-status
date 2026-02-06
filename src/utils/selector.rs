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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_selector_with_fallback_valid() {
        let selector = parse_selector_with_fallback("div", "test");
        // Should parse successfully - verify by using it
        let html = scraper::Html::parse_fragment("<div>test</div>");
        let matches: Vec<_> = html.select(&selector).collect();
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_parse_selector_with_fallback_invalid() {
        let selector = parse_selector_with_fallback("div[invalid", "test");
        // Should use fallback selector that matches nothing
        let html = scraper::Html::parse_fragment("<div>test</div>");
        // Fallback selector "*:not(*)" should not match anything
        let matches: Vec<_> = html.select(&selector).collect();
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_parse_selector_with_fallback_empty() {
        let selector = parse_selector_with_fallback("", "test");
        // Empty selector should fail to parse and use fallback
        let html = scraper::Html::parse_fragment("<div>test</div>");
        let matches: Vec<_> = html.select(&selector).collect();
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_parse_selector_with_fallback_complex_valid() {
        let selector = parse_selector_with_fallback("div.container > p:first-child", "test");
        // Should parse successfully
        let html =
            scraper::Html::parse_fragment("<div class='container'><p>first</p><p>second</p></div>");
        let matches: Vec<_> = html.select(&selector).collect();
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_parse_selector_with_fallback_malformed() {
        // Use a selector that definitely won't parse
        let selector = parse_selector_with_fallback("div[attr='unclosed[", "test");
        // Should use fallback (selector that matches nothing)
        let html = scraper::Html::parse_fragment("<div attr='unclosed'>test</div>");
        let matches: Vec<_> = html.select(&selector).collect();
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_parse_selector_with_fallback_special_characters() {
        // Test with various special characters that might appear in selectors
        let selector = parse_selector_with_fallback("div#id.class[attr='value']", "test");
        let html =
            scraper::Html::parse_fragment("<div id='id' class='class' attr='value'>test</div>");
        let matches: Vec<_> = html.select(&selector).collect();
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_parse_selector_with_fallback_pseudo_selectors() {
        let selector = parse_selector_with_fallback("div:nth-child(2)", "test");
        let html = scraper::Html::parse_fragment("<div>first</div><div>second</div>");
        let matches: Vec<_> = html.select(&selector).collect();
        assert_eq!(matches.len(), 1);
    }
}
