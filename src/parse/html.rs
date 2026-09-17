//! Basic HTML extraction utilities.
//!
//! This module provides functions to extract basic HTML elements:
//! - Page title
//! - Meta description

use scraper::{Html, Selector};
use std::sync::LazyLock;

use crate::error_handling::ProcessingStats;

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
/// Fallback when `.text()` yields no content (see [`extract_title`]); it removes
/// markup delimiters but leaves entity references (e.g. `&amp;`) as-is.
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
/// Uses the first `<title>` element (first-wins). Missing title increments a
/// warning and returns an empty string.
pub fn extract_title(document: &Html, error_stats: &ProcessingStats) -> String {
    let Some(element) = document.select(&TITLE_SELECTOR).next() else {
        error_stats.increment_warning(crate::error_handling::WarningType::MissingTitle);
        return String::new();
    };

    let title: String = element.text().collect::<String>().trim().to_string();
    if !title.is_empty() {
        return title;
    }

    // `<title>` is a RAWTEXT element per HTML5, so html5ever never parses its
    // contents as child elements/comments — text() is the correct, literal
    // content for every well-formed document. This branch is a defensive
    // fallback for parser edge cases.
    let inner = strip_html_tags(&element.inner_html()).trim().to_string();
    if inner.is_empty() {
        error_stats.increment_warning(crate::error_handling::WarningType::MissingTitle);
        String::new()
    } else {
        inner
    }
}

/// Extracts the meta description from an HTML document.
///
/// Searches for `<meta name="description">` and returns its content, trimmed.
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

    if meta_description.is_none() {
        stats.increment_warning(crate::error_handling::WarningType::MissingMetaDescription);
    }
    meta_description
}

#[cfg(test)]
mod strip_html_tags_tests {
    use super::strip_html_tags;

    #[test]
    fn test_strip_html_tags_leaves_entities_untouched() {
        assert_eq!(
            strip_html_tags("Fish &amp; Chips <i>Ltd</i>"),
            "Fish &amp; Chips Ltd"
        );
    }
}
