//! HTML parsing and data extraction.
//!
//! This module extracts structured data from HTML content including:
//! - Meta tags (description, Open Graph, Twitter Cards)
//! - Structured data (JSON-LD `@type`, including `@graph`)
//! - Analytics IDs (Google Analytics, Facebook Pixel, GTM, `AdSense`)
//! - Social media links
//!
//! All HTML walks use CSS selectors via the `scraper` crate. Secret detection
//! is a separate gitleaks-derived path over raw body/header text.

mod analytics;
mod contact;
pub(crate) mod gitleaks;
mod html;
pub mod jwt;
mod secrets;
mod social;
mod structured;

pub use analytics::{extract_analytics_ids, AnalyticsId};
pub use contact::{extract_contact_links, ContactLink};
pub use html::{extract_meta_description, extract_title};
pub use secrets::{detect_exposed_secrets, detect_exposed_secrets_in_headers, ExposedSecret};
pub use social::{extract_social_media_links, SocialMediaLink};
pub use structured::{extract_structured_data, StructuredData};

#[cfg(test)]
pub use analytics::AnalyticsProvider;
#[cfg(test)]
pub use contact::ContactType;
#[cfg(test)]
pub use secrets::SecretSeverity;
#[cfg(test)]
pub use social::SocialPlatform;

#[cfg(test)]
mod tests {
    include!("tests.rs");
}

#[cfg(test)]
#[path = "secrets_corpus.rs"]
mod secrets_corpus;
