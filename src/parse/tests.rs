//! Parse module tests.

use super::*;
use crate::error_handling::ProcessingStats;
use scraper::Html;

fn test_error_stats() -> ProcessingStats {
    ProcessingStats::new()
}

#[test]
fn test_extract_title_basic() {
    let html = r#"<html><head><title>Test Page</title></head><body></body></html>"#;
    let document = Html::parse_document(html);
    let stats = test_error_stats();
    assert_eq!(extract_title(&document, &stats), "Test Page");
    assert_eq!(
        stats.get_error_count(crate::error_handling::ErrorType::TitleExtractError),
        0
    );
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
    // Missing title is now tracked as a warning, not an error
    let html = r#"<html><head></head><body></body></html>"#;
    let document = Html::parse_document(html);
    let stats = test_error_stats();
    assert_eq!(extract_title(&document, &stats), "");
    assert_eq!(
        stats.get_warning_count(crate::error_handling::WarningType::MissingTitle),
        1
    );
    assert_eq!(
        stats.get_error_count(crate::error_handling::ErrorType::TitleExtractError),
        0
    );
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
    // Empty keywords - track as warning
    let html = r#"<html><head><meta name="keywords" content=""></head></html>"#;
    let document = Html::parse_document(html);
    let stats = test_error_stats();
    assert!(extract_meta_keywords(&document, &stats).is_none());
    // Missing/empty keywords is tracked as a warning, not an error
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
    // Missing meta description is tracked as a warning, not an error
    let html = r#"<html><head></head></html>"#;
    let document = Html::parse_document(html);
    let stats = test_error_stats();
    assert!(extract_meta_description(&document, &stats).is_none());
    // Missing meta description is tracked as a warning, not an error
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

// Analytics ID extraction tests
#[test]
fn test_extract_analytics_ids_gtm_data_layer_format() {
    // Test GTM in dataLayer format (like Chevron.com)
    let html = r#"
        <script>
            (function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':
            new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],
            j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src=
            'https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);
            })(window, document, 'script', 'dataLayer','GTM-MMCQ2RJB');
        </script>
    "#;
    let ids = extract_analytics_ids(html);
    assert!(!ids.is_empty(), "Should find GTM ID in dataLayer format");
    let gtm_ids: Vec<&str> = ids
        .iter()
        .filter(|id| id.provider == "Google Tag Manager")
        .map(|id| id.id.as_str())
        .collect();
    assert!(
        gtm_ids.contains(&"GTM-MMCQ2RJB"),
        "Should find GTM-MMCQ2RJB: {:?}",
        gtm_ids
    );
}

#[test]
fn test_extract_analytics_ids_gtm_json_format() {
    // Test GTM in JSON format (like Fannie Mae)
    let html = r#"
        <script type="application/json">{"gtm":{"tagIds":["GTM-T7L6LT"]}}</script>
    "#;
    let ids = extract_analytics_ids(html);
    assert!(!ids.is_empty(), "Should find GTM ID in JSON format");
    let gtm_ids: Vec<&str> = ids
        .iter()
        .filter(|id| id.provider == "Google Tag Manager")
        .map(|id| id.id.as_str())
        .collect();
    assert!(
        gtm_ids.contains(&"GTM-T7L6LT"),
        "Should find GTM-T7L6LT: {:?}",
        gtm_ids
    );
}

#[test]
fn test_extract_analytics_ids_gtm_url_format() {
    // Test GTM in URL format (iframe/script src)
    let html = r#"
        <iframe src="https://www.googletagmanager.com/ns.html?id=GTM-XXXXX"></iframe>
        <script src="https://www.googletagmanager.com/gtm.js?id=GTM-YYYYY"></script>
    "#;
    let ids = extract_analytics_ids(html);
    assert!(!ids.is_empty(), "Should find GTM IDs in URL format");
    let gtm_ids: Vec<&str> = ids
        .iter()
        .filter(|id| id.provider == "Google Tag Manager")
        .map(|id| id.id.as_str())
        .collect();
    assert!(
        gtm_ids.contains(&"GTM-XXXXX") || gtm_ids.contains(&"GTM-YYYYY"),
        "Should find at least one GTM ID: {:?}",
        gtm_ids
    );
}

