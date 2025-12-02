//! Enrichment data insertion.
//!
//! This module handles inserting enrichment data for URL records:
//! - GeoIP data
//! - Structured data (JSON-LD, Open Graph, Twitter Cards, Schema.org)
//! - Social media links
//! - Security warnings
//! - WHOIS data
//! - Analytics/tracking IDs

mod analytics;
mod geoip;
mod security;
mod social;
mod structured;
mod whois;

pub use analytics::insert_analytics_ids;
pub use geoip::insert_geoip_data;
pub use security::insert_security_warnings;
pub use social::insert_social_media_links;
pub use structured::insert_structured_data;
pub use whois::insert_whois_data;

