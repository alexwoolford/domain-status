//! HTML parsing and content extraction.

use log::debug;
use scraper::Html;
use std::collections::{HashMap, HashSet};

use crate::parse::{
    detect_exposed_secrets, extract_contact_links, extract_meta_description,
    extract_social_media_links, extract_structured_data, extract_title,
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
/// Extracted HTML data including title, description, structured data, etc.
#[allow(clippy::too_many_lines)] // Single-pass HTML tree walk extracting ~15 distinct data types
#[allow(clippy::cognitive_complexity)] // Each HTML element type requires distinct extraction logic
pub(crate) fn parse_html_content(
    body: &str,
    final_domain: &str,
    error_stats: &crate::error_handling::ProcessingStats,
) -> HtmlData {
    let document = Html::parse_document(body);

    let title = extract_title(&document, error_stats);
    debug!("Extracted title for {final_domain}: {title:?}");

    let description = extract_meta_description(&document, error_stats);
    debug!("Extracted description for {final_domain}: {description:?}");

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

    // Extract contact links (mailto/tel)
    let contact_links = extract_contact_links(&document);
    debug!(
        "Extracted {} contact links for {final_domain}",
        contact_links.len()
    );

    // Detect exposed secrets in HTML body
    let exposed_secrets = detect_exposed_secrets(body);
    if !exposed_secrets.is_empty() {
        log::info!(
            "Detected {} exposed secret(s) for {final_domain}",
            exposed_secrets.len()
        );
    }

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
    let mut script_tag_ids = HashSet::new();
    let mut inline_script_parts: Vec<String> = Vec::new();
    let script_selector =
        crate::utils::parse_selector_with_fallback("script", "script tag extraction");
    for element in document.select(&script_selector) {
        // Extract script tag IDs (for __NEXT_DATA__ etc.)
        if let Some(id) = element.value().attr("id") {
            script_tag_ids.insert(id.to_string());
        }
        // Extract script src URLs (skip empty src attributes)
        let src = element.value().attr("src").filter(|s| !s.is_empty());
        if let Some(src) = src {
            script_sources.push(src.to_string());
            continue;
        }
        // Inline script bodies for Wappalyzer `scripts` patterns (static text only).
        // Skip JSON-LD / application/json payloads to reduce noise.
        let script_type = element
            .value()
            .attr("type")
            .unwrap_or("")
            .to_ascii_lowercase();
        if script_type.contains("ld+json") || script_type.contains("json") {
            continue;
        }
        let text: String = element.text().collect();
        let trimmed = text.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Skip JSON payloads (JSON-LD without type, Next.js __NEXT_DATA__, etc.)
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            continue;
        }
        inline_script_parts.push(text);
    }
    let inline_script_text = inline_script_parts.join("\n").to_lowercase();
    // Fallback: Use regex to extract script sources that scraper might have missed
    // This is a safety net for edge cases where the HTML parser might miss script tags
    use std::sync::LazyLock;
    static SCRIPT_SRC_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#"(?i)<script[^>]*src\s*=\s*["']([^"']+)["']"#)
            .expect("hardcoded script src regex")
    });
    let script_src_regex = &*SCRIPT_SRC_RE;

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
        "Extracted {} script tag ids and {} external script sources for {} ({} from scraper, {} added via regex fallback)",
        script_tag_ids.len(),
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
                identified_scripts.push(format!("{src} (jQuery)"));
            } else if src_lower.contains("react") {
                identified_scripts.push(format!("{src} (React)"));
            } else if src_lower.contains("adobe")
                || src_lower.contains("dtm")
                || src_lower.contains("satellite")
            {
                identified_scripts.push(format!("{src} (Adobe DTM)"));
            } else if src_lower.contains("salesforce") || src_lower.contains("sfdc") {
                identified_scripts.push(format!("{src} (Salesforce)"));
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

    // Extract canonical URL from <link rel="canonical">
    let canonical_selector = crate::utils::parse_selector_with_fallback(
        r#"link[rel="canonical"]"#,
        "canonical link extraction",
    );
    let canonical_url = document.select(&canonical_selector).find_map(|el| {
        el.value()
            .attr("href")
            .filter(|href| !href.is_empty())
            .map(std::string::ToString::to_string)
    });
    debug!("Extracted canonical URL for {final_domain}: {canonical_url:?}");

    // Extract meta refresh redirect URL from <meta http-equiv="refresh" content="0;url=...">
    let meta_refresh_url = meta_tags
        .get("http-equiv:refresh")
        .and_then(|values| values.first())
        .and_then(|content| {
            // Parse content like "0;url=https://example.com" or "5; URL=https://example.com"
            let lower = content.to_lowercase();
            if let Some(pos) = lower.find("url=") {
                let url_part = content[pos + 4..].trim().to_string();
                if url_part.is_empty() {
                    None
                } else {
                    Some(url_part)
                }
            } else {
                None
            }
        });
    debug!("Extracted meta refresh URL for {final_domain}: {meta_refresh_url:?}");

    // Extract resource hints: cross-origin hints (preconnect, dns-prefetch) are
    // normalized to a bare hostname, while resource-fetch hints (preload, prefetch,
    // modulepreload) usually point at same-origin paths, so their href is kept as-is.
    let hint_selector = crate::utils::parse_selector_with_fallback(
        r#"link[rel="preconnect"], link[rel="dns-prefetch"], link[rel="preload"], link[rel="prefetch"], link[rel="modulepreload"]"#,
        "resource hint extraction",
    );
    let resource_hints: Vec<(String, String)> = document
        .select(&hint_selector)
        .filter_map(|el| {
            let rel = el.value().attr("rel")?;
            let href = el.value().attr("href").filter(|h| !h.is_empty())?;
            let rel_lower = rel.to_ascii_lowercase();
            let value = if matches!(rel_lower.as_str(), "preconnect" | "dns-prefetch") {
                // Extract hostname from href (handles https://host, //host, and bare host)
                let hostname = if href.starts_with("//") {
                    url::Url::parse(&format!("https:{href}"))
                        .ok()
                        .and_then(|u| u.host_str().map(str::to_lowercase))
                } else if href.starts_with("http://") || href.starts_with("https://") {
                    url::Url::parse(href)
                        .ok()
                        .and_then(|u| u.host_str().map(str::to_lowercase))
                } else {
                    // Bare hostname like "fonts.googleapis.com"
                    Some(href.trim_end_matches('/').to_lowercase())
                }?;
                if hostname.is_empty() || !hostname.contains('.') {
                    return None;
                }
                hostname
            } else {
                // preload/prefetch/modulepreload: keep the resource href as-is
                // (typically a same-origin path, not a hostname).
                href.to_string()
            };
            Some((rel_lower, value))
        })
        .collect();
    debug!(
        "Extracted {} resource hints for {final_domain}",
        resource_hints.len()
    );

    // Extract favicon URL from <link rel="icon"> or <link rel="shortcut icon">
    let favicon_selector = crate::utils::parse_selector_with_fallback(
        r#"link[rel~="icon"], link[rel="shortcut icon"]"#,
        "favicon link extraction",
    );
    let favicon_url = document.select(&favicon_selector).find_map(|el| {
        el.value()
            .attr("href")
            .filter(|href| !href.is_empty())
            .map(std::string::ToString::to_string)
    });
    debug!("Extracted favicon URL for {final_domain}: {favicon_url:?}");

    let meta_robots = meta_tags
        .get("name:robots")
        .and_then(|values| values.first())
        .filter(|v| !v.is_empty())
        .cloned();

    HtmlData {
        title,
        description,
        structured_data,
        social_media_links,
        contact_links,
        exposed_secrets,
        analytics_ids,
        meta_tags,
        script_sources,
        script_tag_ids,
        inline_script_text,
        external_scripts_eligible: 0,
        external_scripts_scanned: 0,
        favicon_url,
        canonical_url,
        meta_refresh_url,
        meta_robots,
        resource_hints,
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
        assert_eq!(result.description, Some("A test page".to_string()));
    }

    #[test]
    fn test_parse_html_meta_robots() {
        let html = r#"
            <html><head>
                <title>t</title>
                <meta name="robots" content="noindex, nofollow">
            </head><body></body></html>
        "#;
        let stats = test_error_stats();
        let result = parse_html_content(html, "example.com", &stats);
        assert_eq!(result.meta_robots.as_deref(), Some("noindex, nofollow"));
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
    fn test_parse_html_content_resource_hints() {
        let html = r#"
            <html>
                <head>
                    <link rel="preconnect" href="https://fonts.googleapis.com">
                    <link rel="dns-prefetch" href="//cdn.example.com">
                    <link rel="preload" href="/assets/app.css" as="style">
                    <link rel="prefetch" href="/next-page.html">
                    <link rel="modulepreload" href="/js/module.mjs">
                </head>
                <body></body>
            </html>
        "#;
        let stats = test_error_stats();
        let result = parse_html_content(html, "example.com", &stats);

        assert!(result
            .resource_hints
            .contains(&("preconnect".to_string(), "fonts.googleapis.com".to_string())));
        assert!(result
            .resource_hints
            .contains(&("dns-prefetch".to_string(), "cdn.example.com".to_string())));
        // preload/prefetch/modulepreload keep the href as-is (same-origin paths, not hostnames)
        assert!(result
            .resource_hints
            .contains(&("preload".to_string(), "/assets/app.css".to_string())));
        assert!(result
            .resource_hints
            .contains(&("prefetch".to_string(), "/next-page.html".to_string())));
        assert!(result
            .resource_hints
            .contains(&("modulepreload".to_string(), "/js/module.mjs".to_string())));
        assert_eq!(result.resource_hints.len(), 5);
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
        // Inline scripts (non-JSON) feed fingerprint `scripts` patterns
        assert!(result.inline_script_text.contains("console.log"));
        // JSON payloads in script tags are skipped
        assert!(!result.inline_script_text.contains("\"page\""));
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
    fn test_parse_html_content_empty_html() {
        let html = "<html><head></head><body></body></html>";
        let stats = test_error_stats();
        let result = parse_html_content(html, "example.com", &stats);

        assert_eq!(result.title, "");
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
        assert!(result
            .script_sources
            .contains(&"https://example.com/script1.js".to_string()));
        assert!(result
            .script_sources
            .contains(&"https://example.com/script2.js".to_string()));
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
        assert!(result.description.is_some());

        // Error stats are passed to extract_title / extract_meta_description
        // If any of those functions encounter errors, they should update error_stats
        // The key is that error_stats is accessible to those functions
        // We can't easily trigger errors in those functions, but we verify the parameter is passed
        // by ensuring the function doesn't panic and completes successfully
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
