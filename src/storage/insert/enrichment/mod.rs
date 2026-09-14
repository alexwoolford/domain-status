//! Enrichment data insertion.
//!
//! This module handles inserting enrichment data for URL records:
//! - `GeoIP` data
//! - Structured data (JSON-LD, Open Graph, Twitter Cards, Schema.org)
//! - Social media links
//! - WHOIS data
//! - Analytics/tracking IDs

mod analytics;
mod contact;
mod favicon;
mod geoip;
mod jwt_claims;
mod secrets;
mod social;
mod structured;
mod whois;

pub(crate) use analytics::insert_analytics_ids_in_tx;
pub(crate) use contact::insert_contact_links_in_tx;
pub(crate) use favicon::insert_favicon_data_in_tx;
pub(crate) use geoip::insert_geoip_data_in_tx;
pub(crate) use jwt_claims::insert_jwt_claims_batch_in_tx;
#[cfg(test)]
pub use secrets::insert_exposed_secrets;
pub(crate) use secrets::insert_exposed_secrets_in_tx;
pub(crate) use social::insert_social_media_links_in_tx;
pub(crate) use structured::insert_structured_data_in_tx;
pub(crate) use whois::insert_whois_data_in_tx;
