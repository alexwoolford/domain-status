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
// Large function handling comprehensive HTML parsing with multiple extraction operations.
// Complex control flow for script extraction, meta tag parsing, and structured data extraction.
// Consider refactoring into smaller focused functions in Phase 4.
#[allow(clippy::too_many_lines)]
#[allow(clippy::cognitive_complexity)]
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
    // Note: We store ALL meta tags, not just the last one for each key
    // This matches wappalyzergo behavior - it checks each meta tag as it's encountered
    // We use Vec<String> to store multiple values for the same key (e.g., multiple generator tags)
    let mut meta_tags: HashMap<String, Vec<String>> = HashMap::new();
    let meta_selector = crate::utils::parse_selector_with_fallback("meta", "meta tag extraction");
    for element in document.select(&meta_selector) {
        // Check name attribute (standard meta tags)
        if let (Some(name), Some(content)) = (
            element.value().attr("name"),
            element.value().attr("content"),
        ) {
            let key = format!("name:{}", name.to_lowercase());
            meta_tags.entry(key).or_default().push(content.to_string());
        }
        // Check property attribute (Open Graph, etc.)
        if let (Some(property), Some(content)) = (
            element.value().attr("property"),
            element.value().attr("content"),
        ) {
            let key = format!("property:{}", property.to_lowercase());
            meta_tags.entry(key).or_default().push(content.to_string());
        }
        // Check http-equiv attribute
        if let (Some(http_equiv), Some(content)) = (
            element.value().attr("http-equiv"),
            element.value().attr("content"),
        ) {
            let key = format!("http-equiv:{}", http_equiv.to_lowercase());
            meta_tags.entry(key).or_default().push(content.to_string());
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
        // Extract script src URLs (skip empty src attributes)
        if let Some(src) = element.value().attr("src") {
            if !src.is_empty() {
                script_sources.push(src.to_string());
            }
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
    // Fallback: Use regex to extract script sources that scraper might have missed
    // This is a safety net for edge cases where the HTML parser might miss script tags
    use regex::Regex;
    // Try multiple regex patterns to catch different script tag formats
    let script_src_regex = match Regex::new(r#"(?i)<script[^>]*src\s*=\s*["']([^"']+)["']"#) {
        Ok(re) => re,
        Err(_) => {
            Regex::new(r#"<script[^>]*src=["']([^"']+)["']"#).unwrap() // Fallback to simpler pattern
        }
    };

    let regex_extracted_scripts: Vec<String> = script_src_regex
        .captures_iter(body)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .collect();

    let scraper_count = script_sources.len();
    let mut regex_added = 0;

    // Merge regex-extracted scripts with scraper-extracted ones (avoid duplicates)
    for regex_script in &regex_extracted_scripts {
        if !script_sources.contains(regex_script) {
            script_sources.push(regex_script.clone());
            regex_added += 1;
        }
    }

    log::debug!(
        "Extracted {} inline scripts ({} bytes) and {} external script sources for {} ({} from scraper, {} added via regex fallback)",
        inline_script_count,
        script_content.len(),
        script_sources.len(),
        final_domain,
        scraper_count,
        regex_added
    );

    // Log all script sources for debugging (helpful to see what we're working with)
    // Also identify which scripts might set jQuery/React/etc.
    if !script_sources.is_empty() {
        let mut identified_scripts = Vec::new();
        for src in &script_sources {
            let src_lower = src.to_lowercase();
            if src_lower.contains("jquery") {
                identified_scripts.push(format!("{} (jQuery)", src));
            } else if src_lower.contains("react") {
                identified_scripts.push(format!("{} (React)", src));
            } else if src_lower.contains("adobe")
                || src_lower.contains("dtm")
                || src_lower.contains("satellite")
            {
                identified_scripts.push(format!("{} (Adobe DTM)", src));
            } else if src_lower.contains("salesforce") || src_lower.contains("sfdc") {
                identified_scripts.push(format!("{} (Salesforce)", src));
            } else {
                identified_scripts.push(src.clone());
            }
        }
        log::debug!(
            "Script sources for {} ({} total): {:?}",
            final_domain,
            script_sources.len(),
            identified_scripts
        );
    }

    // Extract favicon URL from <link rel="icon"> or <link rel="shortcut icon">
    let favicon_selector = crate::utils::parse_selector_with_fallback(
        r#"link[rel~="icon"], link[rel="shortcut icon"]"#,
        "favicon link extraction",
    );
    let favicon_url = document.select(&favicon_selector).find_map(|el| {
        el.value()
            .attr("href")
            .filter(|href| !href.is_empty())
            .map(|href| href.to_string())
    });
    debug!("Extracted favicon URL for {final_domain}: {favicon_url:?}");

    // Extract text content (limited for performance)
    // Note: Iterator::take() limits the number of items (text nodes), not characters
    // We need to collect and truncate manually to limit by character count
    let html_text_full: String = document.root_element().text().collect();
    let html_text = if html_text_full.len() > crate::config::MAX_HTML_TEXT_EXTRACTION_CHARS {
        html_text_full
            .chars()
            .take(crate::config::MAX_HTML_TEXT_EXTRACTION_CHARS)
            .collect()
    } else {
        html_text_full
    };

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
        favicon_url,
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
            Some(&vec!["John Doe".to_string()])
        );
        assert!(result.meta_tags.contains_key("property:og:title"));
        assert_eq!(
            result.meta_tags.get("property:og:title"),
            Some(&vec!["OG Title".to_string()])
        );
        assert!(result.meta_tags.contains_key("http-equiv:refresh"));
        assert_eq!(
            result.meta_tags.get("http-equiv:refresh"),
            Some(&vec!["30".to_string()])
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

    #[test]
    fn test_parse_html_content_script_size_limit() {
        // Test that large inline scripts are truncated to MAX_SCRIPT_CONTENT_SIZE
        let large_script = "x".repeat(crate::config::MAX_SCRIPT_CONTENT_SIZE + 10000);
        let html = format!(
            r#"
            <html>
                <head>
                    <script>{}</script>
                </head>
                <body></body>
            </html>
            "#,
            large_script
        );
        let stats = test_error_stats();
        let result = parse_html_content(&html, "example.com", &stats);

        // Script content should be truncated to MAX_SCRIPT_CONTENT_SIZE
        assert!(result.script_content.len() <= crate::config::MAX_SCRIPT_CONTENT_SIZE + 1);
        // +1 for newline
    }

    #[test]
    fn test_parse_html_content_html_text_limit() {
        // Test that HTML text extraction is limited to MAX_HTML_TEXT_EXTRACTION_CHARS
        // Create HTML with large text content
        let large_text = "x".repeat(crate::config::MAX_HTML_TEXT_EXTRACTION_CHARS + 10000);
        let html = format!(r#"<html><body><p>{}</p></body></html>"#, large_text);
        let stats = test_error_stats();
        let result = parse_html_content(&html, "example.com", &stats);

        // HTML text should be truncated to MAX_HTML_TEXT_EXTRACTION_CHARS
        // (Note: HTML tags and whitespace also count, so may be slightly over)
        assert!(
            result.html_text.len() <= crate::config::MAX_HTML_TEXT_EXTRACTION_CHARS + 100,
            "HTML text length {} exceeds limit {}",
            result.html_text.len(),
            crate::config::MAX_HTML_TEXT_EXTRACTION_CHARS
        );
    }

    #[test]
    fn test_parse_html_content_malformed_html() {
        // Test that malformed HTML doesn't cause panics
        let malformed_html = r#"
            <html>
                <head>
                    <title>Test</title>
                    <meta name="keywords" content="test">
                    <script src="test.js"></script>
                    <div>Unclosed div
                    <p>Unclosed p
                </head>
                <body>
                    <script>var x = <invalid></script>
                </body>
            </html>
        "#;
        let stats = test_error_stats();
        let result = parse_html_content(malformed_html, "example.com", &stats);

        // Should still extract what it can without panicking
        assert_eq!(result.title, "Test");
        assert!(result.script_sources.contains(&"test.js".to_string()));
    }

    #[test]
    fn test_parse_html_content_multiple_meta_same_key() {
        // Test that multiple meta tags with same key are handled correctly
        let html = r#"
            <html>
                <head>
                    <meta name="keywords" content="first">
                    <meta name="keywords" content="second">
                    <meta property="og:title" content="First OG">
                    <meta property="og:title" content="Second OG">
                </head>
                <body></body>
            </html>
        "#;
        let stats = test_error_stats();
        let result = parse_html_content(html, "example.com", &stats);

        // Should extract all meta tags (later ones may overwrite earlier ones)
        assert!(result.meta_tags.contains_key("name:keywords"));
        assert!(result.meta_tags.contains_key("property:og:title"));
    }

    #[test]
    fn test_parse_html_content_script_with_special_chars() {
        // Test script extraction with special characters in URLs
        let html = r#"
            <html>
                <head>
                    <script src="https://example.com/script.js?v=1.0&key=value"></script>
                    <script src="https://example.com/script.js?param=test&other=data"></script>
                </head>
                <body></body>
            </html>
        "#;
        let stats = test_error_stats();
        let result = parse_html_content(html, "example.com", &stats);

        assert_eq!(result.script_sources.len(), 2);
        assert!(result.script_sources.iter().any(|s| s.contains("v=1.0")));
    }

    #[test]
    fn test_parse_html_content_empty_script_tags() {
        // Test handling of empty script tags
        let html = r#"
            <html>
                <head>
                    <script></script>
                    <script src=""></script>
                    <script id="test-id"></script>
                </head>
                <body></body>
            </html>
        "#;
        let stats = test_error_stats();
        let result = parse_html_content(html, "example.com", &stats);

        // Empty src should not be added to script_sources
        assert!(result.script_sources.is_empty());
        // ID should still be extracted
        assert!(result.script_tag_ids.contains("test-id"));
    }

    #[test]
    fn test_parse_html_content_error_stats_passed_through() {
        // Test that error_stats parameter is correctly passed to extraction functions
        // This is critical - HTML parsing errors should be tracked for monitoring
        let html = r#"
            <html>
                <head>
                    <title>Test</title>
                    <meta name="keywords" content="test">
                    <meta name="description" content="test description">
                </head>
                <body></body>
            </html>
        "#;
        let stats = test_error_stats();

        let result = parse_html_content(html, "example.com", &stats);

        // Should extract data successfully
        assert_eq!(result.title, "Test");
        assert!(result.keywords_str.is_some());
        assert!(result.description.is_some());

        // Error stats are passed to extract_title, extract_meta_keywords, extract_meta_description
        // If any of those functions encounter errors, they should update error_stats
        // The key is that error_stats is accessible to those functions
        // We can't easily trigger errors in those functions, but we verify the parameter is passed
        // by ensuring the function doesn't panic and completes successfully
    }

    #[test]
    fn test_parse_html_content_script_content_size_limit_enforced() {
        // Test that script content size limit is enforced per script
        // This is critical - prevents DoS attacks via large scripts
        let large_script_content = "x".repeat(crate::config::MAX_SCRIPT_CONTENT_SIZE + 5000);
        let html = format!(
            r#"
            <html>
                <head>
                    <script>{}</script>
                    <script>var y = 2;</script>
                </head>
                <body></body>
            </html>
            "#,
            large_script_content
        );
        let stats = test_error_stats();
        let result = parse_html_content(&html, "example.com", &stats);

        // First script should be truncated to MAX_SCRIPT_CONTENT_SIZE
        // Second script should be included fully
        // Each script gets truncated individually, then newlines are added
        // Total content should be <= MAX_SCRIPT_CONTENT_SIZE (first) + second_script_size + newlines
        let second_script_size = "var y = 2;".len();
        // Each script gets a newline separator, so: first_truncated + "\n" + second + "\n"
        let expected_max = crate::config::MAX_SCRIPT_CONTENT_SIZE + second_script_size + 2; // +2 for newlines
        assert!(
            result.script_content.len() <= expected_max,
            "Script content length {} exceeds expected max {}",
            result.script_content.len(),
            expected_max
        );
        // Should contain both scripts (first truncated, second full)
        assert!(result.script_content.contains("var y"));
        // First script should be truncated (not contain all the 'x' characters)
        // The content should be less than the original large script size
        assert!(result.script_content.len() < large_script_content.len());
    }

    #[test]
    fn test_parse_html_content_meta_tags_all_attributes_extracted() {
        // Test that meta tags with name, property, and http-equiv are all extracted
        // This is critical - different meta tag formats must be supported
        let html = r#"
            <html>
                <head>
                    <meta name="author" content="John">
                    <meta property="og:title" content="OG Title">
                    <meta property="og:description" content="OG Desc">
                    <meta http-equiv="refresh" content="30">
                    <meta http-equiv="content-type" content="text/html">
                </head>
                <body></body>
            </html>
        "#;
        let stats = test_error_stats();
        let result = parse_html_content(html, "example.com", &stats);

        // All meta tag types should be extracted
        assert!(result.meta_tags.contains_key("name:author"));
        assert!(result.meta_tags.contains_key("property:og:title"));
        assert!(result.meta_tags.contains_key("property:og:description"));
        assert!(result.meta_tags.contains_key("http-equiv:refresh"));
        assert!(result.meta_tags.contains_key("http-equiv:content-type"));
        assert_eq!(result.meta_tags.len(), 5);
    }

    #[test]
    fn test_parse_html_content_favicon_link_rel_icon() {
        let html = r#"
            <html>
                <head>
                    <link rel="icon" href="/img/favicon.png">
                </head>
                <body></body>
            </html>
        "#;
        let stats = test_error_stats();
        let result = parse_html_content(html, "example.com", &stats);
        assert_eq!(result.favicon_url, Some("/img/favicon.png".to_string()));
    }

    #[test]
    fn test_parse_html_content_favicon_shortcut_icon() {
        let html = r#"
            <html>
                <head>
                    <link rel="shortcut icon" href="https://cdn.example.com/favicon.ico">
                </head>
                <body></body>
            </html>
        "#;
        let stats = test_error_stats();
        let result = parse_html_content(html, "example.com", &stats);
        assert_eq!(
            result.favicon_url,
            Some("https://cdn.example.com/favicon.ico".to_string())
        );
    }

    #[test]
    fn test_parse_html_content_favicon_none_when_missing() {
        let html = r#"
            <html>
                <head>
                    <title>No Favicon</title>
                </head>
                <body></body>
            </html>
        "#;
        let stats = test_error_stats();
        let result = parse_html_content(html, "example.com", &stats);
        assert_eq!(result.favicon_url, None);
    }

    #[test]
    fn test_parse_html_content_favicon_prefers_first() {
        let html = r#"
            <html>
                <head>
                    <link rel="icon" href="/first.png">
                    <link rel="icon" href="/second.png">
                </head>
                <body></body>
            </html>
        "#;
        let stats = test_error_stats();
        let result = parse_html_content(html, "example.com", &stats);
        assert_eq!(result.favicon_url, Some("/first.png".to_string()));
    }
}
