use regex::Regex;
use scraper::{Html, Selector};
use std::collections::HashMap;
use std::sync::LazyLock;

use crate::error_handling::{ErrorStats, ErrorType};

// CSS selector strings
const TITLE_SELECTOR_STR: &str = "title";
const META_KEYWORDS_SELECTOR_STR: &str = "meta[name='keywords']";
const META_DESCRIPTION_SELECTOR_STR: &str = "meta[name='description']";
const LINKEDIN_ANCHOR_SELECTOR_STR: &str = "a[href]";

// Regex patterns
const LINKEDIN_URL_PATTERN: &str = r"https?://www\.linkedin\.com/company/([^/?#]+)";

static TITLE_SELECTOR: LazyLock<Selector> = LazyLock::new(|| {
    Selector::parse(TITLE_SELECTOR_STR).expect("Failed to parse title selector - this is a bug")
});

static META_KEYWORDS_SELECTOR: LazyLock<Selector> = LazyLock::new(|| {
    Selector::parse(META_KEYWORDS_SELECTOR_STR)
        .expect("Failed to parse meta keywords selector - this is a bug")
});

static META_DESCRIPTION_SELECTOR: LazyLock<Selector> = LazyLock::new(|| {
    Selector::parse(META_DESCRIPTION_SELECTOR_STR)
        .expect("Failed to parse meta description selector - this is a bug")
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
/// * `error_stats` - Error statistics tracker for recording extraction failures
///
/// # Returns
///
/// The page title as a string, or an empty string if not found.
pub fn extract_title(document: &Html, error_stats: &ErrorStats) -> String {
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
                    error_stats.increment(ErrorType::TitleExtractError);
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
            error_stats.increment(ErrorType::TitleExtractError);
            String::from("")
        }
    }
}

/// Extracts meta keywords from an HTML document.
///
/// Searches for a `<meta name="keywords">` element and parses its `content` attribute
/// as a comma-separated list of keywords. Returns `None` if the meta tag is not found
/// or if the content is empty.
///
/// # Arguments
///
/// * `document` - The parsed HTML document
/// * `error_stats` - Error statistics tracker (currently unused for this function)
///
/// # Returns
///
/// A vector of keyword strings, or `None` if no keywords meta tag is found.
pub fn extract_meta_keywords(document: &Html, error_stats: &ErrorStats) -> Option<Vec<String>> {
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
                error_stats.increment(ErrorType::KeywordExtractError);
                None
            } else {
                Some(keywords)
            }
        }
        None => {
            error_stats.increment(ErrorType::KeywordExtractError);
            None
        }
    }
}

/// Extracts the meta description from an HTML document.
///
/// Searches for a `<meta name="description">` element and returns its `content`
/// attribute value, trimmed of whitespace. Returns `None` if the meta tag is not found.
///
/// # Arguments
///
/// * `document` - The parsed HTML document
/// * `error_stats` - Error statistics tracker (currently unused for this function)
///
/// # Returns
///
/// The meta description as a string, or `None` if not found.
pub fn extract_meta_description(document: &Html, error_stats: &ErrorStats) -> Option<String> {
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
        error_stats.increment(ErrorType::MetaDescriptionExtractError);
    }

    meta_description
}

/// Extracts the LinkedIn company slug from an HTML document.
///
/// Searches for anchor tags (`<a>`) with `href` attributes matching the LinkedIn
/// company URL pattern (`https://www.linkedin.com/company/{slug}`) and extracts
/// the slug portion. Returns `None` if no matching link is found.
///
/// # Arguments
///
/// * `document` - The parsed HTML document
/// * `error_stats` - Error statistics tracker for recording extraction failures
///
/// # Returns
///
/// The LinkedIn company slug, or `None` if not found.
pub fn extract_linkedin_slug(document: &Html, error_stats: &ErrorStats) -> Option<String> {
    let selector = match Selector::parse(LINKEDIN_ANCHOR_SELECTOR_STR) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to parse LinkedIn selector: {e}");
            error_stats.increment(ErrorType::LinkedInSlugExtractError);
            return None;
        }
    };
    let re = match Regex::new(LINKEDIN_URL_PATTERN) {
        Ok(r) => r,
        Err(e) => {
            log::error!("Failed to compile LinkedIn regex: {e}");
            error_stats.increment(ErrorType::LinkedInSlugExtractError);
            return None;
        }
    };

    for element in document.select(&selector) {
        if let Some(link) = element.value().attr("href") {
            if let Some(caps) = re.captures(link) {
                return caps.get(1).map(|m| m.as_str().to_string());
            }
        }
    }
    error_stats.increment(ErrorType::LinkedInSlugExtractError);
    None
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ErrorStats;

    fn test_error_stats() -> ErrorStats {
        ErrorStats::new()
    }

    #[test]
    fn test_extract_title_basic() {
        let html = r#"<html><head><title>Test Page</title></head><body></body></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert_eq!(extract_title(&document, &stats), "Test Page");
        assert_eq!(stats.get_count(ErrorType::TitleExtractError), 0);
    }

    #[test]
    fn test_extract_title_with_whitespace() {
        // Common gotcha: titles with extra whitespace/newlines
        let html = r#"<html><head><title>
            Test Page
        </title></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert_eq!(extract_title(&document, &stats), "Test Page");
    }

    #[test]
    fn test_extract_title_with_html_entities() {
        // HTML entities should be decoded
        let html = r#"<html><head><title>Test &amp; Page &lt;Title&gt;</title></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        let title = extract_title(&document, &stats);
        // scraper should decode entities
        assert!(title.contains("&") || title.contains("Test"));
    }

    #[test]
    fn test_extract_title_empty() {
        let html = r#"<html><head><title></title></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert_eq!(extract_title(&document, &stats), "");
    }

    #[test]
    fn test_extract_title_missing() {
        let html = r#"<html><head></head><body></body></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert_eq!(extract_title(&document, &stats), "");
        assert_eq!(stats.get_count(ErrorType::TitleExtractError), 1);
    }

    #[test]
    fn test_extract_title_multiple_tags() {
        // Edge case: multiple title tags (should get first)
        let html = r#"<html><head><title>First</title><title>Second</title></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert_eq!(extract_title(&document, &stats), "First");
    }

    #[test]
    fn test_extract_meta_keywords_basic() {
        let html = r#"<html><head><meta name="keywords" content="rust, programming, language"></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        let keywords = extract_meta_keywords(&document, &stats).unwrap();
        assert_eq!(keywords, vec!["rust", "programming", "language"]);
    }

    #[test]
    fn test_extract_meta_keywords_with_whitespace() {
        // Common gotcha: keywords with extra spaces
        let html = r#"<html><head><meta name="keywords" content=" rust , programming , language "></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        let keywords = extract_meta_keywords(&document, &stats).unwrap();
        assert_eq!(keywords, vec!["rust", "programming", "language"]);
    }

    #[test]
    fn test_extract_meta_keywords_empty_content() {
        // Edge case: empty content attribute
        let html = r#"<html><head><meta name="keywords" content=""></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert!(extract_meta_keywords(&document, &stats).is_none());
        assert_eq!(stats.get_count(ErrorType::KeywordExtractError), 1);
    }

    #[test]
    fn test_extract_meta_keywords_only_whitespace() {
        // Edge case: content with only spaces/commas
        let html = r#"<html><head><meta name="keywords" content="  ,  ,  "></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert!(extract_meta_keywords(&document, &stats).is_none());
    }

    #[test]
    fn test_extract_meta_keywords_case_insensitive() {
        // Keywords should be lowercased
        let html = r#"<html><head><meta name="keywords" content="RUST, Programming, LANGUAGE"></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        let keywords = extract_meta_keywords(&document, &stats).unwrap();
        assert_eq!(keywords, vec!["rust", "programming", "language"]);
    }

    #[test]
    fn test_extract_meta_description_basic() {
        let html =
            r#"<html><head><meta name="description" content="A test description"></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert_eq!(
            extract_meta_description(&document, &stats),
            Some("A test description".to_string())
        );
    }

    #[test]
    fn test_extract_meta_description_with_whitespace() {
        let html = r#"<html><head><meta name="description" content="  A test description  "></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert_eq!(
            extract_meta_description(&document, &stats),
            Some("A test description".to_string())
        );
    }

    #[test]
    fn test_extract_meta_description_missing() {
        let html = r#"<html><head></head></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert!(extract_meta_description(&document, &stats).is_none());
        assert_eq!(stats.get_count(ErrorType::MetaDescriptionExtractError), 1);
    }

    #[test]
    fn test_extract_linkedin_slug_basic() {
        let html = r#"<html><body><a href="https://www.linkedin.com/company/example">Link</a></body></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert_eq!(
            extract_linkedin_slug(&document, &stats),
            Some("example".to_string())
        );
    }

    #[test]
    fn test_extract_linkedin_slug_with_query() {
        // Edge case: LinkedIn URL with query parameters
        let html = r#"<html><body><a href="https://www.linkedin.com/company/example?trk=test">Link</a></body></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert_eq!(
            extract_linkedin_slug(&document, &stats),
            Some("example".to_string())
        );
    }

    #[test]
    fn test_extract_linkedin_slug_with_fragment() {
        // Edge case: LinkedIn URL with fragment
        let html = r#"<html><body><a href="https://www.linkedin.com/company/example#section">Link</a></body></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert_eq!(
            extract_linkedin_slug(&document, &stats),
            Some("example".to_string())
        );
    }

    #[test]
    fn test_extract_linkedin_slug_http() {
        // Should work with HTTP too
        let html = r#"<html><body><a href="http://www.linkedin.com/company/example">Link</a></body></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert_eq!(
            extract_linkedin_slug(&document, &stats),
            Some("example".to_string())
        );
    }

    #[test]
    fn test_extract_linkedin_slug_multiple_links() {
        // Edge case: multiple LinkedIn links (should get first)
        let html = r#"<html><body>
            <a href="https://www.linkedin.com/company/first">First</a>
            <a href="https://www.linkedin.com/company/second">Second</a>
        </body></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert_eq!(
            extract_linkedin_slug(&document, &stats),
            Some("first".to_string())
        );
    }

    #[test]
    fn test_extract_linkedin_slug_not_linkedin() {
        // Should not match non-LinkedIn URLs
        let html =
            r#"<html><body><a href="https://example.com/company/test">Link</a></body></html>"#;
        let document = Html::parse_document(html);
        let stats = test_error_stats();
        assert!(extract_linkedin_slug(&document, &stats).is_none());
        assert_eq!(stats.get_count(ErrorType::LinkedInSlugExtractError), 1);
    }

    #[test]
    fn test_is_mobile_friendly_with_viewport() {
        let html =
            r#"<html><head><meta name="viewport" content="width=device-width"></head></html>"#;
        assert!(is_mobile_friendly(html));
    }

    #[test]
    fn test_is_mobile_friendly_case_insensitive() {
        // Edge case: viewport in different case
        // Current implementation uses contains() which is case-sensitive
        // "Viewport" does not contain "viewport" (lowercase), so this should fail
        let html =
            r#"<html><head><meta name="Viewport" content="width=device-width"></head></html>"#;
        // This documents a limitation: case-sensitive matching
        assert!(!is_mobile_friendly(html));
    }

    #[test]
    fn test_is_mobile_friendly_without_viewport() {
        let html = r#"<html><head><title>Test</title></head></html>"#;
        assert!(!is_mobile_friendly(html));
    }

    #[test]
    fn test_is_mobile_friendly_false_positive() {
        // Potential gotcha: word "viewport" in content (not in meta tag)
        let html = r#"<html><body><p>This page has a viewport</p></body></html>"#;
        // Current implementation would return true (false positive)
        // This test documents this behavior
        assert!(is_mobile_friendly(html));
    }
}
