//! Structured data extraction.
//!
//! This module extracts structured data from HTML documents including:
//! - JSON-LD (`application/ld+json` script tags)
//! - Open Graph meta tags (`og:*`)
//! - Twitter Card meta tags (`twitter:*`)
//! - Schema.org types from JSON-LD `@type` (including `@graph`)

use scraper::{Html, Selector};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::LazyLock;

/// Structured data extracted from HTML.
#[derive(Debug, Clone, Default)]
pub struct StructuredData {
    /// JSON-LD scripts (`application/ld+json`)
    pub json_ld: Vec<Value>,
    /// Open Graph meta tags (`og:*`)
    pub open_graph: HashMap<String, String>,
    /// Twitter Card meta tags (`twitter:*`)
    pub twitter_cards: HashMap<String, String>,
    /// Schema.org types from JSON-LD `@type`, including nodes under `@graph`.
    pub schema_types: Vec<String>,
}

/// Extracts structured data from an HTML document.
///
/// Extracts:
/// - JSON-LD (`script type="application/ld+json"`)
/// - Open Graph tags (`meta property="og:*"`)
/// - Twitter Card tags (`meta name="twitter:*"`)
/// - Schema.org types from JSON-LD `@type` (top-level and `@graph`)
pub fn extract_structured_data(document: &Html) -> StructuredData {
    let json_ld = extract_json_ld(document);
    let mut schema_types = Vec::new();
    for json_value in &json_ld {
        collect_schema_types(json_value, &mut schema_types);
    }

    StructuredData {
        json_ld,
        open_graph: extract_open_graph(document),
        twitter_cards: extract_twitter_cards(document),
        schema_types,
    }
}

fn is_json_ld_script_type(script_type: &str) -> bool {
    script_type
        .split(';')
        .next()
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/ld+json"))
}

fn push_schema_type(schema_types: &mut Vec<String>, type_str: &str) {
    let trimmed = type_str.trim();
    if !trimmed.is_empty() {
        schema_types.push(trimmed.to_string());
    }
}

fn push_type_value(type_value: &Value, schema_types: &mut Vec<String>) {
    if let Some(type_str) = type_value.as_str() {
        push_schema_type(schema_types, type_str);
    } else if let Some(type_array) = type_value.as_array() {
        for t in type_array {
            if let Some(t_str) = t.as_str() {
                push_schema_type(schema_types, t_str);
            }
        }
    }
}

/// Collects `@type` from an object and from each node in `@graph`.
fn collect_schema_types(value: &Value, schema_types: &mut Vec<String>) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_schema_types(item, schema_types);
            }
        }
        Value::Object(obj) => {
            if let Some(type_value) = obj.get("@type") {
                push_type_value(type_value, schema_types);
            }
            if let Some(graph) = obj.get("@graph") {
                collect_schema_types(graph, schema_types);
            }
        }
        _ => {}
    }
}

fn parse_json_ld_block(json_str: &str, json_ld_scripts: &mut Vec<Value>) {
    let json_str = json_str.trim();
    if json_str.is_empty() {
        return;
    }
    if let Ok(json_array) = serde_json::from_str::<Vec<Value>>(json_str) {
        json_ld_scripts.extend(json_array);
    } else if let Ok(json_value) = serde_json::from_str::<Value>(json_str) {
        json_ld_scripts.push(json_value);
    }
}

/// Extracts JSON-LD from `script` tags whose type is `application/ld+json`.
fn extract_json_ld(document: &Html) -> Vec<Value> {
    static SCRIPT_SELECTOR: LazyLock<Selector> = LazyLock::new(|| {
        Selector::parse("script").expect("script selector is a hardcoded valid CSS selector")
    });

    let mut json_ld_scripts = Vec::new();
    for element in document.select(&SCRIPT_SELECTOR) {
        let Some(script_type) = element.value().attr("type") else {
            continue;
        };
        if !is_json_ld_script_type(script_type) {
            continue;
        }
        let json_str: String = element.text().collect();
        parse_json_ld_block(&json_str, &mut json_ld_scripts);
    }
    json_ld_scripts
}

fn extract_open_graph(document: &Html) -> HashMap<String, String> {
    let mut og_tags = HashMap::new();

    static OG_SELECTOR: LazyLock<Selector> =
        LazyLock::new(|| Selector::parse(r#"meta[property^="og:"]"#).expect("OG selector"));
    for element in document.select(&OG_SELECTOR) {
        if let (Some(property), Some(content)) = (
            element.value().attr("property"),
            element.value().attr("content"),
        ) {
            og_tags.insert(property.to_string(), content.to_string());
        }
    }
    og_tags
}

fn extract_twitter_cards(document: &Html) -> HashMap<String, String> {
    let mut twitter_tags = HashMap::new();

    static TWITTER_SELECTOR: LazyLock<Selector> = LazyLock::new(|| {
        Selector::parse(r#"meta[name^="twitter:"]"#).expect("Twitter card selector")
    });
    for element in document.select(&TWITTER_SELECTOR) {
        if let (Some(name), Some(content)) = (
            element.value().attr("name"),
            element.value().attr("content"),
        ) {
            twitter_tags.insert(name.to_string(), content.to_string());
        }
    }
    twitter_tags
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract(html: &str) -> StructuredData {
        let document = Html::parse_document(html);
        extract_structured_data(&document)
    }

    #[test]
    fn test_extract_structured_data_json_ld() {
        let html = r#"
            <html>
                <head>
                    <script type="application/ld+json">
                        {"@type": "WebPage", "name": "Test Page"}
                    </script>
                </head>
            </html>
        "#;
        let data = extract(html);
        assert_eq!(data.json_ld.len(), 1);
        assert_eq!(data.json_ld[0]["@type"], "WebPage");
    }

    #[test]
    fn test_extract_structured_data_json_ld_array() {
        let html = r#"<html><head><script type="application/ld+json">[{"@type": "WebPage"}, {"@type": "Organization"}]</script></head></html>"#;
        let data = extract(html);
        assert_eq!(data.json_ld.len(), 2);
        assert!(data.schema_types.contains(&"WebPage".to_string()));
        assert!(data.schema_types.contains(&"Organization".to_string()));
    }

    #[test]
    fn test_extract_structured_data_schema_types() {
        let html = r#"<html><head><script type="application/ld+json">{"@type": "WebPage"}</script></head></html>"#;
        let data = extract(html);
        assert!(data.schema_types.contains(&"WebPage".to_string()));
    }

    #[test]
    fn test_extract_structured_data_schema_types_array() {
        let html = r#"<html><head><script type="application/ld+json">{"@type": ["WebPage", "Article"]}</script></head></html>"#;
        let data = extract(html);
        assert!(data.schema_types.contains(&"WebPage".to_string()));
        assert!(data.schema_types.contains(&"Article".to_string()));
    }

    #[test]
    fn test_extract_structured_data_schema_types_from_graph() {
        let html = r#"<html><head><script type="application/ld+json">{"@context":"https://schema.org","@graph":[{"@type":"Organization","name":"Example"},{"@type":"WebSite"}]}</script></head></html>"#;
        let data = extract(html);
        assert_eq!(data.json_ld.len(), 1);
        assert!(data.schema_types.contains(&"Organization".to_string()));
        assert!(data.schema_types.contains(&"WebSite".to_string()));
    }

    #[test]
    fn test_extract_structured_data_json_ld_type_attribute_order() {
        let html = r#"<html><head><script id="ld" type="application/ld+json">{"@type":"WebPage"}</script></head></html>"#;
        let data = extract(html);
        assert_eq!(data.json_ld.len(), 1);
        assert_eq!(data.schema_types, vec!["WebPage".to_string()]);
    }

    #[test]
    fn test_extract_structured_data_open_graph() {
        let html = r#"
            <html>
                <head>
                    <meta property="og:title" content="Test Title" />
                    <meta property="og:description" content="Test Description" />
                </head>
            </html>
        "#;
        let data = extract(html);
        assert_eq!(
            data.open_graph.get("og:title"),
            Some(&"Test Title".to_string())
        );
        assert_eq!(
            data.open_graph.get("og:description"),
            Some(&"Test Description".to_string())
        );
    }

    #[test]
    fn test_extract_structured_data_twitter_cards() {
        let html = r#"
            <html>
                <head>
                    <meta name="twitter:card" content="summary" />
                    <meta name="twitter:title" content="Test Title" />
                </head>
            </html>
        "#;
        let data = extract(html);
        assert_eq!(
            data.twitter_cards.get("twitter:card"),
            Some(&"summary".to_string())
        );
        assert_eq!(
            data.twitter_cards.get("twitter:title"),
            Some(&"Test Title".to_string())
        );
    }

    #[test]
    fn test_extract_structured_data_all_types() {
        let html = r#"
            <html>
                <head>
                    <script type="application/ld+json">
                        {"@type": "WebPage"}
                    </script>
                    <meta property="og:title" content="Test" />
                    <meta name="twitter:card" content="summary" />
                </head>
            </html>
        "#;
        let data = extract(html);
        assert!(!data.json_ld.is_empty());
        assert!(!data.open_graph.is_empty());
        assert!(!data.twitter_cards.is_empty());
        assert!(!data.schema_types.is_empty());
    }

    #[test]
    fn test_extract_structured_data_empty() {
        let html = "<html><body>No structured data</body></html>";
        let data = extract(html);
        assert!(data.json_ld.is_empty());
        assert!(data.open_graph.is_empty());
        assert!(data.twitter_cards.is_empty());
        assert!(data.schema_types.is_empty());
    }

    #[test]
    fn test_extract_structured_data_json_ld_single_quotes() {
        let html = r#"<html><head><script type='application/ld+json'>{"@type": "WebPage"}</script></head></html>"#;
        let data = extract(html);
        assert_eq!(data.json_ld.len(), 1);
    }

    #[test]
    fn test_extract_structured_data_json_ld_case_insensitive() {
        let html = r#"<html><head><script TYPE="APPLICATION/LD+JSON">{"@type": "WebPage"}</script></head></html>"#;
        let data = extract(html);
        assert_eq!(data.json_ld.len(), 1);
    }

    #[test]
    fn test_extract_structured_data_skips_blank_schema_type() {
        let html =
            r#"<html><head><script type="application/ld+json">{"@type":""}</script></head></html>"#;
        let data = extract(html);
        assert_eq!(data.json_ld.len(), 1);
        assert!(data.schema_types.is_empty());
    }

    #[test]
    fn test_extract_structured_data_skips_blank_schema_type_in_array() {
        let html = r#"<html><head><script type="application/ld+json">{"@type":["", " Article "]}</script></head></html>"#;
        let data = extract(html);
        assert_eq!(data.schema_types, vec!["Article".to_string()]);
    }
}
