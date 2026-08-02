//! HTML parsing and data extraction.
//!
//! This module extracts structured data from HTML content including:
//! - Meta tags (description, Open Graph, Twitter Cards)
//! - Structured data (JSON-LD, microdata)
//! - Analytics IDs (Google Analytics, Facebook Pixel, GTM, `AdSense`)
//! - Social media links
//!
//! All parsing is done using CSS selectors via the `scraper` crate.

mod analytics;
mod contact;
pub(crate) mod gitleaks;
mod html;
pub mod jwt;
mod secrets;
mod social;
mod structured;

// Re-export public API
#[allow(unused_imports)] // Public API re-export
pub use analytics::{extract_analytics_ids, AnalyticsId, AnalyticsProvider};
#[allow(unused_imports)] // Public API re-export
pub use contact::{extract_contact_links, ContactLink, ContactType};
#[allow(unused_imports)] // Public API re-export
pub use html::{extract_meta_description, extract_title};
#[allow(unused_imports)] // Public API re-export
pub use secrets::{
    detect_exposed_secrets, detect_exposed_secrets_in_headers, ExposedSecret, SecretSeverity,
};
#[allow(unused_imports)] // Public API re-export
pub use social::{extract_social_media_links, SocialMediaLink, SocialPlatform};
pub use structured::{extract_structured_data, StructuredData};

#[cfg(test)]
mod tests {
    include!("tests.rs");
}

#[cfg(test)]
#[path = "secrets_corpus.rs"]
mod secrets_corpus;
