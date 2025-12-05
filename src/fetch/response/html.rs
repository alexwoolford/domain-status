//! HTML parsing and content extraction.

use log::debug;
use scraper::Html;
use std::collections::{HashMap, HashSet};

use crate::parse::{
    extract_meta_description, extract_meta_keywords, extract_social_media_links,
    extract_structured_data, extract_title, is_mobile_friendly,
};

use super::types::HtmlData;

/// Parses HTML content and extracts all relevant data.
///
/// # Arguments
///
/// * `body` - The HTML body content
/// * `final_domain` - The final domain (for logging)
/// * `error_stats` - Processing statistics tracker
///
/// # Returns
///
/// Extracted HTML data including title, keywords, description, structured data, etc.
pub(crate) fn parse_html_content(
    body: &str,
    final_domain: &str,
    error_stats: &crate::error_handling::ProcessingStats,
) -> HtmlData {
    let document = Html::parse_document(body);

    let title = extract_title(&document, error_stats);
    debug!("Extracted title for {final_domain}: {title:?}");

    let keywords = extract_meta_keywords(&document, error_stats);
    let keywords_str = keywords.map(|kw| kw.join(", "));
    debug!("Extracted keywords for {final_domain}: {keywords_str:?}");

    let description = extract_meta_description(&document, error_stats);
    debug!("Extracted description for {final_domain}: {description:?}");

    let is_mobile_friendly = is_mobile_friendly(body);

    // Extract structured data (JSON-LD, Open Graph, Twitter Cards, Schema.org)
    let structured_data = extract_structured_data(&document, body);
    debug!(
        "Extracted structured data for {final_domain}: {} JSON-LD scripts, {} OG tags, {} Twitter tags, {} schema types",
        structured_data.json_ld.len(),
        structured_data.open_graph.len(),
        structured_data.twitter_cards.len(),
        structured_data.schema_types.len()
    );

    // Extract social media links
    let social_media_links = extract_social_media_links(&document);
    debug!(
        "Extracted {} social media links for {final_domain}",
        social_media_links.len()
    );

    // Extract analytics/tracking IDs (GA, Facebook Pixel, GTM, AdSense)
    let analytics_ids = crate::parse::extract_analytics_ids(body);
    debug!(
        "Extracted {} analytics IDs for {final_domain}: {:?}",
        analytics_ids.len(),
        analytics_ids
    );

    // Extract data needed for technology detection (to avoid double-parsing)
    let mut meta_tags = HashMap::new();
    let meta_selector = crate::utils::parse_selector_with_fallback("meta", "meta tag extraction");
    for element in document.select(&meta_selector) {
        // Check name attribute (standard meta tags)
        if let (Some(name), Some(content)) = (
            element.value().attr("name"),
            element.value().attr("content"),
        ) {
            meta_tags.insert(format!("name:{}", name.to_lowercase()), content.to_string());
        }
        // Check property attribute (Open Graph, etc.)
        if let (Some(property), Some(content)) = (
            element.value().attr("property"),
            element.value().attr("content"),
        ) {
            meta_tags.insert(
                format!("property:{}", property.to_lowercase()),
                content.to_string(),
            );
        }
        // Check http-equiv attribute
        if let (Some(http_equiv), Some(content)) = (
            element.value().attr("http-equiv"),
            element.value().attr("content"),
        ) {
            meta_tags.insert(
                format!("http-equiv:{}", http_equiv.to_lowercase()),
                content.to_string(),
            );
        }
    }

    let mut script_sources = Vec::new();
    let mut script_content = String::new();
    let mut script_tag_ids = HashSet::new();
    let mut inline_script_count = 0;
    let script_selector =
        crate::utils::parse_selector_with_fallback("script", "script tag extraction");
    for element in document.select(&script_selector) {
        // Extract script tag IDs (for __NEXT_DATA__ etc.)
        if let Some(id) = element.value().attr("id") {
            script_tag_ids.insert(id.to_string());
        }
        // Extract script src URLs
        if let Some(src) = element.value().attr("src") {
            script_sources.push(src.to_string());
        }
        // Extract inline script content (limited to MAX_SCRIPT_CONTENT_SIZE per script for security)
        // This prevents DoS attacks via large scripts
        if element.value().attr("src").is_none() {
            let text = element.text().collect::<String>();
            if !text.trim().is_empty() {
                inline_script_count += 1;
                script_content.push_str(
                    &text
                        .chars()
                        .take(crate::config::MAX_SCRIPT_CONTENT_SIZE)
                        .collect::<String>(),
                );
                script_content.push('\n'); // Separate scripts with newline
            }
        }
    }
    log::debug!(
        "Extracted {} inline scripts ({} bytes) and {} external script sources for {}",
        inline_script_count,
        script_content.len(),
        script_sources.len(),
        final_domain
    );

    // Extract text content (limited for performance)
    let html_text: String = document
        .root_element()
        .text()
        .take(crate::config::MAX_HTML_TEXT_EXTRACTION_CHARS)
        .collect();

    HtmlData {
        title,
        keywords_str,
        description,
        is_mobile_friendly,
        structured_data,
        social_media_links,
        analytics_ids,
        meta_tags,
        script_sources,
        script_content,
        script_tag_ids,
        html_text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_handling::ProcessingStats;

    fn test_error_stats() -> ProcessingStats {
        ProcessingStats::new()
    }

    #[test]
    fn test_parse_html_content_basic() {
        let html = r#"
            <html>
                <head>
                    <title>Test Page</title>
                    <meta name="keywords" content="test, page">
                    <meta name="description" content="A test page">
                </head>
                <body>
                    <p>Hello, world!</p>
                </body>
            </html>
        "#;
        let stats = test_error_stats();
        let result = parse_html_content(html, "example.com", &stats);

        assert_eq!(result.title, "Test Page");
        assert_eq!(result.keywords_str, Some("test, page".to_string()));
        assert_eq!(result.description, Some("A test page".to_string()));
        assert!(result.html_text.contains("Hello"));
    }

    #[test]
    fn test_parse_html_content_meta_tags() {
        let html = r#"
            <html>
                <head>
                    <meta name="author" content="John Doe">
                    <meta property="og:title" content="OG Title">
                    <meta http-equiv="refresh" content="30">
                </head>
                <body></body>
            </html>
        "#;
        let stats = test_error_stats();
        let result = parse_html_content(html, "example.com", &stats);

        // Check meta tags extraction
        assert!(result.meta_tags.contains_key("name:author"));
        assert_eq!(
            result.meta_tags.get("name:author"),
            Some(&"John Doe".to_string())
        );
        assert!(result.meta_tags.contains_key("property:og:title"));
        assert_eq!(
            result.meta_tags.get("property:og:title"),
            Some(&"OG Title".to_string())
        );
        assert!(result.meta_tags.contains_key("http-equiv:refresh"));
        assert_eq!(
            result.meta_tags.get("http-equiv:refresh"),
            Some(&"30".to_string())
        );
    }

    #[test]
    fn test_parse_html_content_script_extraction() {
        let html = r#"
            <html>
                <head>
                    <script src="https://example.com/script.js"></script>
                    <script id="__NEXT_DATA__">{"page":"test"}</script>
                    <script>console.log("inline");</script>
                </head>
                <body></body>
            </html>
        "#;
        let stats = test_error_stats();
        let result = parse_html_content(html, "example.com", &stats);

        // Check script sources
        assert_eq!(result.script_sources.len(), 1);
        assert!(result
            .script_sources
            .contains(&"https://example.com/script.js".to_string()));

        // Check script IDs
        assert!(result.script_tag_ids.contains("__NEXT_DATA__"));

        // Check inline script content
        assert!(result.script_content.contains("console.log"));
    }

    #[test]
    fn test_parse_html_content_social_media_links() {
        let html = r#"
            <html>
                <body>
                    <a href="https://twitter.com/example">Twitter</a>
                    <a href="https://www.linkedin.com/company/example">LinkedIn</a>
                    <a href="https://github.com/example">GitHub</a>
                </body>
            </html>
        "#;
        let stats = test_error_stats();
        let result = parse_html_content(html, "example.com", &stats);

        assert!(!result.social_media_links.is_empty());
        let platforms: Vec<&str> = result
            .social_media_links
            .iter()
            .map(|link| link.platform.as_str())
            .collect();
        assert!(platforms.contains(&"Twitter") || platforms.contains(&"X"));
        assert!(platforms.contains(&"LinkedIn"));
        assert!(platforms.contains(&"GitHub"));
    }

    #[test]
    fn test_parse_html_content_analytics_ids() {
        let html = r#"
            <html>
                <head>
                    <script>
                        ga('create', 'UA-123456-1', 'auto');
                        gtag('config', 'G-XXXXXXXXXX');
                    </script>
                </head>
                <body></body>
            </html>
        "#;
        let stats = test_error_stats();
        let result = parse_html_content(html, "example.com", &stats);

        assert!(!result.analytics_ids.is_empty());
        let providers: Vec<&str> = result
            .analytics_ids
            .iter()
            .map(|id| id.provider.as_str())
            .collect();
        assert!(providers.contains(&"Google Analytics"));
    }

    #[test]
    fn test_parse_html_content_structured_data() {
        let html = r#"
            <html>
                <head>
                    <script type="application/ld+json">{"@type":"WebPage","name":"Test"}</script>
                    <meta property="og:title" content="OG Title">
                    <meta name="twitter:card" content="summary">
                </head>
                <body></body>
            </html>
        "#;
        let stats = test_error_stats();
        let result = parse_html_content(html, "example.com", &stats);

        // Check structured data - JSON-LD might be empty if parsing fails, but OG and Twitter should work
        // Open Graph and Twitter Cards are extracted from meta tags
        assert!(!result.structured_data.open_graph.is_empty());
        assert!(!result.structured_data.twitter_cards.is_empty());
        // JSON-LD extraction depends on valid JSON - may be empty if JSON is invalid
        // We just verify the function doesn't panic
    }

    #[test]
    fn test_parse_html_content_mobile_friendly() {
        let html_with_viewport = r#"
            <html>
                <head>
                    <meta name="viewport" content="width=device-width, initial-scale=1">
                </head>
                <body></body>
            </html>
        "#;
        let html_without_viewport = r#"
            <html>
                <head></head>
                <body></body>
            </html>
        "#;
        let stats = test_error_stats();

        let result_with = parse_html_content(html_with_viewport, "example.com", &stats);
        assert!(result_with.is_mobile_friendly);

        let result_without = parse_html_content(html_without_viewport, "example.com", &stats);
        assert!(!result_without.is_mobile_friendly);
    }

    #[test]
    fn test_parse_html_content_empty_html() {
        let html = "<html><head></head><body></body></html>";
        let stats = test_error_stats();
        let result = parse_html_content(html, "example.com", &stats);

        assert_eq!(result.title, "");
        assert_eq!(result.keywords_str, None);
        assert_eq!(result.description, None);
        assert!(result.script_sources.is_empty());
        assert!(result.social_media_links.is_empty());
        assert!(result.analytics_ids.is_empty());
    }

    #[test]
    fn test_parse_html_content_multiple_scripts() {
        let html = r#"
            <html>
                <head>
                    <script src="https://example.com/script1.js"></script>
                    <script src="https://example.com/script2.js"></script>
                    <script>var x = 1;</script>
                    <script>var y = 2;</script>
                </head>
                <body></body>
            </html>
        "#;
        let stats = test_error_stats();
        let result = parse_html_content(html, "example.com", &stats);

        assert_eq!(result.script_sources.len(), 2);
        assert!(result.script_content.contains("var x"));
        assert!(result.script_content.contains("var y"));
    }

    #[test]
    fn test_parse_html_content_meta_tags_case_insensitive() {
        let html = r#"
            <html>
                <head>
                    <meta NAME="keywords" CONTENT="test">
                    <meta PROPERTY="og:title" CONTENT="Title">
                </head>
                <body></body>
            </html>
        "#;
        let stats = test_error_stats();
        let result = parse_html_content(html, "example.com", &stats);

        // Meta tag keys should be lowercased
        assert!(result.meta_tags.contains_key("name:keywords"));
        assert!(result.meta_tags.contains_key("property:og:title"));
    }
}
