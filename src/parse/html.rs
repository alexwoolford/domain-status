//! Basic HTML extraction utilities.
//!
//! This module provides functions to extract basic HTML elements:
//! - Page title
//! - Meta description

use scraper::{Html, Selector};
use std::sync::LazyLock;

use crate::error_handling::ProcessingStats;

// CSS selector strings
const TITLE_SELECTOR_STR: &str = "title";
const META_DESCRIPTION_SELECTOR_STR: &str = "meta[name='description']";
static TITLE_SELECTOR: LazyLock<Selector> = LazyLock::new(|| {
    Selector::parse(TITLE_SELECTOR_STR)
        .expect("TITLE_SELECTOR_STR is a hardcoded valid CSS selector; this is a compile-time bug")
});

static META_DESCRIPTION_SELECTOR: LazyLock<Selector> = LazyLock::new(|| {
    Selector::parse(META_DESCRIPTION_SELECTOR_STR)
        .expect("META_DESCRIPTION_SELECTOR_STR is a hardcoded valid CSS selector; this is a compile-time bug")
});

/// Strips HTML tags (`<...>` spans) from a string without touching entities.
///
/// This is a minimal, non-parsing strip used only as a fallback when `.text()`
/// yields no content (see [`extract_title`]); it removes markup delimiters but
/// leaves entity references (e.g. `&amp;`) exactly as-is for the caller to decode
/// or display as needed.
fn strip_html_tags(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => result.push(ch),
            _ => {}
        }
    }
    result
}

/// Extracts the page title from an HTML document.
///
/// Searches for the first `<title>` element and returns its text content, trimmed
/// of whitespace. If no title is found, increments the error counter and returns
/// an empty string.
///
/// # Arguments
///
/// * `document` - The parsed HTML document
/// * `error_stats` - Processing statistics tracker for recording extraction issues
///
/// # Returns
///
/// The page title as a string, or an empty string if not found.
pub fn extract_title(document: &Html, error_stats: &ProcessingStats) -> String {
    let elements: Vec<_> = document.select(&TITLE_SELECTOR).collect();
    log::debug!("Found {} title elements", elements.len());

    if let Some(element) = elements.first() {
        // Use text() to get text content, which handles HTML entities and nested tags correctly
        let title: String = element.text().collect::<String>().trim().to_string();
        log::debug!(
            "Extracted title text: '{}' (length: {})",
            title,
            title.len()
        );
        if title.is_empty() {
            // `<title>` is a RAWTEXT element per HTML5, so html5ever never parses its
            // contents as child elements/comments — text() (above) is the correct,
            // literal content for every well-formed document, and this branch is not
            // expected to be reachable in practice. It's kept as a defensive fallback
            // for parser edge cases; if it's ever hit, strip markup-looking tags so we
            // don't leak raw HTML into the stored title (entities are left untouched
            // since we only remove `<...>` spans, not decode text).
            let inner = strip_html_tags(&element.inner_html()).trim().to_string();
            log::debug!("Title inner_html: '{}' (length: {})", inner, inner.len());
            if inner.is_empty() {
                error_stats.increment_warning(crate::error_handling::WarningType::MissingTitle);
                String::new()
            } else {
                inner
            }
        } else {
            title
        }
    } else {
        log::debug!("No title element found in document");
        error_stats.increment_warning(crate::error_handling::WarningType::MissingTitle);
        String::new()
    }
}

/// Extracts the meta description from an HTML document.
///
/// Searches for `<meta name="description">` and returns its content, trimmed of whitespace.
///
/// # Arguments
///
/// * `document` - The parsed HTML document
/// * `stats` - Processing statistics tracker for recording extraction issues
///
/// # Returns
///
/// The meta description as a string, or `None` if not found.
pub fn extract_meta_description(document: &Html, stats: &ProcessingStats) -> Option<String> {
    let meta_description = document
        .select(&META_DESCRIPTION_SELECTOR)
        .next()
        .and_then(|element| {
            element
                .value()
                .attr("content")
                .map(|content| content.trim().to_string())
        });

    // Missing meta description - track as warning (optional but recommended for SEO)
    if meta_description.is_none() {
        stats.increment_warning(crate::error_handling::WarningType::MissingMetaDescription);
    }
    meta_description
}

#[cfg(test)]
mod strip_html_tags_tests {
    use super::strip_html_tags;

    #[test]
    fn test_strip_html_tags_removes_simple_tags() {
        assert_eq!(strip_html_tags("<b>bold</b> text"), "bold text");
    }

    #[test]
    fn test_strip_html_tags_leaves_entities_untouched() {
        assert_eq!(
            strip_html_tags("Fish &amp; Chips <i>Ltd</i>"),
            "Fish &amp; Chips Ltd"
        );
    }

    #[test]
    fn test_strip_html_tags_strips_comments() {
        assert_eq!(strip_html_tags("<!-- comment -->visible"), "visible");
    }

    #[test]
    fn test_strip_html_tags_no_tags() {
        assert_eq!(strip_html_tags("plain text"), "plain text");
    }

    #[test]
    fn test_strip_html_tags_empty() {
        assert_eq!(strip_html_tags(""), "");
    }
}
