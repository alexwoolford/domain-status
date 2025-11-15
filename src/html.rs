use lazy_static::lazy_static;
use regex::Regex;
use scraper::{Html, Selector};

use crate::error_handling::{ErrorStats, ErrorType};

lazy_static! {
    static ref TITLE_SELECTOR: Selector =
        Selector::parse("title").expect("Failed to parse title selector - this is a bug");
    static ref META_KEYWORDS_SELECTOR: Selector = Selector::parse("meta[name='keywords']")
        .expect("Failed to parse meta keywords selector - this is a bug");
    static ref META_DESCRIPTION_SELECTOR: Selector = Selector::parse("meta[name='description']")
        .expect("Failed to parse meta description selector - this is a bug");
}

/// Extracts the title from an HTML document.
///
/// # Arguments
///
/// * `document` - The parsed HTML document
/// * `error_stats` - Error statistics tracker
///
/// # Returns
///
/// The page title, or an empty string if not found.
pub fn extract_title(document: &Html, error_stats: &ErrorStats) -> String {
    match document.select(&TITLE_SELECTOR).next() {
        Some(element) => element.inner_html().trim().to_string(),
        None => {
            error_stats.increment(ErrorType::TitleExtractError);
            String::from("")
        }
    }
}

/// Extracts meta keywords from an HTML document.
///
/// # Arguments
///
/// * `document` - The parsed HTML document
/// * `error_stats` - Error statistics tracker
///
/// # Returns
///
/// A vector of keyword strings, or `None` if no keywords are found.
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
/// # Arguments
///
/// * `document` - The parsed HTML document
/// * `error_stats` - Error statistics tracker
///
/// # Returns
///
/// The meta description string, or `None` if not found.
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

/// Extracts the LinkedIn company slug from LinkedIn URLs found in the HTML.
///
/// # Arguments
///
/// * `document` - The parsed HTML document
/// * `error_stats` - Error statistics tracker
///
/// # Returns
///
/// The LinkedIn company slug, or `None` if not found.
pub fn extract_linkedin_slug(document: &Html, error_stats: &ErrorStats) -> Option<String> {
    let selector = match Selector::parse("a[href]") {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to parse LinkedIn selector: {e}");
            error_stats.increment(ErrorType::LinkedInSlugExtractError);
            return None;
        }
    };
    let re = match Regex::new(r"https?://www\.linkedin\.com/company/([^/?]+)") {
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
