//! HTML parsing and data extraction.
//!
//! This module extracts structured data from HTML content including:
//! - Meta tags (keywords, description, Open Graph, Twitter Cards)
//! - Structured data (JSON-LD, microdata)
//! - Analytics IDs (Google Analytics, Facebook Pixel, GTM, AdSense)
//! - Social media links
//! - Mobile-friendliness indicators
//!
//! All parsing is done using CSS selectors via the `scraper` crate.

mod analytics;
mod html;
mod social;
mod structured;

// Re-export public API
#[allow(unused_imports)] // Public API re-export
pub use analytics::{extract_analytics_ids, AnalyticsId, AnalyticsProvider};
pub use html::{
    extract_meta_description, extract_meta_keywords, extract_title, is_mobile_friendly,
};
#[allow(unused_imports)] // Public API re-export
pub use social::{extract_social_media_links, SocialMediaLink, SocialPlatform};
pub use structured::{extract_structured_data, StructuredData};

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
