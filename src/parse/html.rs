//! Basic HTML extraction utilities.
//!
//! This module provides functions to extract basic HTML elements:
//! - Page title
//! - Meta keywords
//! - Meta description
//! - Mobile-friendliness detection

use scraper::{Html, Selector};
use std::sync::LazyLock;

use crate::error_handling::ProcessingStats;

// CSS selector strings
const TITLE_SELECTOR_STR: &str = "title";
const META_KEYWORDS_SELECTOR_STR: &str = "meta[name='keywords']";
const META_DESCRIPTION_SELECTOR_STR: &str = "meta[name='description']";

static TITLE_SELECTOR: LazyLock<Selector> = LazyLock::new(|| {
    Selector::parse(TITLE_SELECTOR_STR).unwrap_or_else(|e| {
        log::error!(
            "Failed to parse title selector '{}': {}",
            TITLE_SELECTOR_STR,
            e
        );
        // Return a safe default selector that matches nothing
        // This prevents panics while still allowing the code to run
        // Use a known-valid selector that won't match anything: "*:not(*)"
        crate::utils::parse_selector_unsafe("*:not(*)", "TITLE_SELECTOR fallback")
    })
});

static META_KEYWORDS_SELECTOR: LazyLock<Selector> = LazyLock::new(|| {
    Selector::parse(META_KEYWORDS_SELECTOR_STR).unwrap_or_else(|e| {
        log::error!(
            "Failed to parse meta keywords selector '{}': {}",
            META_KEYWORDS_SELECTOR_STR,
            e
        );
        crate::utils::parse_selector_unsafe("*:not(*)", "META_KEYWORDS_SELECTOR fallback")
    })
});

static META_DESCRIPTION_SELECTOR: LazyLock<Selector> = LazyLock::new(|| {
    Selector::parse(META_DESCRIPTION_SELECTOR_STR).unwrap_or_else(|e| {
        log::error!(
            "Failed to parse meta description selector '{}': {}",
            META_DESCRIPTION_SELECTOR_STR,
            e
        );
        crate::utils::parse_selector_unsafe("*:not(*)", "META_DESCRIPTION_SELECTOR fallback")
    })
});

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

    match elements.first() {
        Some(element) => {
            // Use text() to get text content, which handles HTML entities and nested tags correctly
            let title: String = element.text().collect::<String>().trim().to_string();
            log::debug!(
                "Extracted title text: '{}' (length: {})",
                title,
                title.len()
            );
            if title.is_empty() {
                // Try inner_html as fallback in case text() doesn't work
                let inner = element.inner_html().trim().to_string();
                log::debug!("Title inner_html: '{}' (length: {})", inner, inner.len());
                if inner.is_empty() {
                    error_stats.increment_warning(crate::error_handling::WarningType::MissingTitle);
                    String::from("")
                } else {
                    inner
                }
            } else {
                title
            }
        }
        None => {
            log::debug!("No title element found in document");
            error_stats.increment_warning(crate::error_handling::WarningType::MissingTitle);
            String::from("")
        }
    }
}

/// Extracts meta keywords from an HTML document.
///
/// Searches for `<meta name="keywords">` and parses the comma-separated keywords,
/// trimming whitespace and converting to lowercase.
///
/// # Arguments
///
/// * `document` - The parsed HTML document
/// * `error_stats` - Processing statistics tracker for recording extraction issues
///
/// # Returns
///
/// A vector of keyword strings, or `None` if no keywords meta tag is found or if it's empty.
pub fn extract_meta_keywords(
    document: &Html,
    error_stats: &ProcessingStats,
) -> Option<Vec<String>> {
    let meta_keywords = document
        .select(&META_KEYWORDS_SELECTOR)
        .next()
        .and_then(|element| element.value().attr("content"));

    match meta_keywords {
        Some(content) => {
            let keywords: Vec<String> = content
                .split(',')
                .map(|keyword| keyword.trim().to_lowercase())
                .filter(|keyword| !keyword.is_empty())
                .collect();

            if keywords.is_empty() {
                // Empty keywords - track as warning
                error_stats.increment_warning(crate::error_handling::WarningType::MissingMetaKeywords);
                None
            } else {
                Some(keywords)
            }
        }
        None => {
            // Missing keywords meta tag - track as warning
            error_stats.increment_warning(crate::error_handling::WarningType::MissingMetaKeywords);
            None
        }
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

/// Checks if an HTML document is mobile-friendly by looking for a viewport meta tag.
///
/// # Arguments
///
/// * `html` - The raw HTML content
///
/// # Returns
///
/// `true` if a viewport meta tag is present, `false` otherwise.
pub fn is_mobile_friendly(html: &str) -> bool {
    html.contains("viewport")
}

