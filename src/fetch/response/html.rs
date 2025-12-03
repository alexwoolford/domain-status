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
