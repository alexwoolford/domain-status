//! Structured data extraction.
//!
//! This module extracts structured data from HTML documents including:
//! - JSON-LD (application/ld+json)
//! - Open Graph meta tags (og:*)
//! - Twitter Card meta tags (twitter:*)
//! - Schema.org types

use regex::Regex;
use scraper::{Html, Selector};
use std::collections::HashMap;

/// Structured data extracted from HTML
#[derive(Debug, Clone, Default)]
pub struct StructuredData {
    /// JSON-LD scripts (application/ld+json)
    pub json_ld: Vec<serde_json::Value>,
    /// Open Graph meta tags (og:*)
    pub open_graph: HashMap<String, String>,
    /// Twitter Card meta tags (twitter:*)
    pub twitter_cards: HashMap<String, String>,
    /// Schema.org types detected (from JSON-LD @type or microdata itemtype)
    pub schema_types: Vec<String>,
}

/// Extracts structured data from an HTML document.
///
/// Extracts:
/// - JSON-LD (script type="application/ld+json")
/// - Open Graph tags (meta property="og:*")
/// - Twitter Card tags (meta name="twitter:*")
/// - Schema.org types (from JSON-LD @type)
///
/// # Arguments
///
/// * `document` - The parsed HTML document
/// * `html` - The raw HTML content (for JSON-LD extraction)
///
/// # Returns
///
/// A `StructuredData` struct containing all extracted structured data.
pub fn extract_structured_data(document: &Html, html: &str) -> StructuredData {
    // Extract JSON-LD
    let json_ld = extract_json_ld(html);

    // Extract Schema.org types from JSON-LD
    let mut schema_types = Vec::new();
    for json_value in &json_ld {
        if let Some(obj) = json_value.as_object() {
            if let Some(type_value) = obj.get("@type") {
                if let Some(type_str) = type_value.as_str() {
                    schema_types.push(type_str.to_string());
                } else if let Some(type_array) = type_value.as_array() {
                    for t in type_array {
                        if let Some(t_str) = t.as_str() {
                            schema_types.push(t_str.into());
                        }
                    }
                }
            }
        }
    }

    // Extract Open Graph tags
    let open_graph = extract_open_graph(document);

    // Extract Twitter Card tags
    let twitter_cards = extract_twitter_cards(document);

    StructuredData {
        json_ld,
        open_graph,
        twitter_cards,
        schema_types,
    }
}

/// Extracts JSON-LD structured data from HTML.
///
/// Searches for `<script type="application/ld+json">` tags and parses their content.
fn extract_json_ld(html: &str) -> Vec<serde_json::Value> {
    let mut json_ld_scripts = Vec::new();

    // Pattern to match JSON-LD script tags
    // Matches: <script type="application/ld+json">...</script>
    // Handles both single and double quotes, and case-insensitive type attribute
    // Use two patterns: one for double quotes, one for single quotes
    let re_double = match Regex::new(
        "(?i)<script[^>]*type\\s*=\\s*\"application/ld\\+json\"[^>]*>(.*?)</script>",
    ) {
        Ok(r) => r,
        Err(_) => return json_ld_scripts,
    };

    let re_single = match Regex::new(
        "(?i)<script[^>]*type\\s*=\\s*'application/ld\\+json'[^>]*>(.*?)</script>",
    ) {
        Ok(r) => r,
        Err(_) => return json_ld_scripts,
    };

    // Try double quotes first
    for cap in re_double.captures_iter(html) {
        if let Some(json_content) = cap.get(1) {
            let json_str = json_content.as_str().trim();
            if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(json_str) {
                json_ld_scripts.push(json_value);
            } else {
                // Try parsing as array of JSON objects
                if let Ok(json_array) = serde_json::from_str::<Vec<serde_json::Value>>(json_str) {
                    json_ld_scripts.extend(json_array);
                }
            }
        }
    }

    // Then try single quotes
    for cap in re_single.captures_iter(html) {
        if let Some(json_content) = cap.get(1) {
            let json_str = json_content.as_str().trim();
            if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(json_str) {
                json_ld_scripts.push(json_value);
            } else {
                // Try parsing as array of JSON objects
                if let Ok(json_array) = serde_json::from_str::<Vec<serde_json::Value>>(json_str) {
                    json_ld_scripts.extend(json_array);
                }
            }
        }
    }

    json_ld_scripts
}

/// Extracts Open Graph meta tags from HTML.
///
/// Searches for `<meta property="og:*">` tags and extracts property-value pairs.
fn extract_open_graph(document: &Html) -> HashMap<String, String> {
    let mut og_tags = HashMap::new();

    // Selector for meta tags with property attribute starting with "og:"
    let selector_str = r#"meta[property^="og:"]"#;
    if let Ok(selector) = Selector::parse(selector_str) {
        for element in document.select(&selector) {
            if let (Some(property), Some(content)) = (
                element.value().attr("property"),
                element.value().attr("content"),
            ) {
                og_tags.insert(property.to_string(), content.to_string());
            }
        }
    }

    og_tags
}

/// Extracts Twitter Card meta tags from HTML.
///
/// Searches for `<meta name="twitter:*">` tags and extracts name-value pairs.
fn extract_twitter_cards(document: &Html) -> HashMap<String, String> {
    let mut twitter_tags = HashMap::new();

    // Selector for meta tags with name attribute starting with "twitter:"
    let selector_str = r#"meta[name^="twitter:"]"#;
    if let Ok(selector) = Selector::parse(selector_str) {
        for element in document.select(&selector) {
            if let (Some(name), Some(content)) = (
                element.value().attr("name"),
                element.value().attr("content"),
            ) {
                twitter_tags.insert(name.to_string(), content.to_string());
            }
        }
    }

    twitter_tags
}
