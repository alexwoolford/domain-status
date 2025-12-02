//! GeoIP data structures.
//!
//! This module defines the data structures used for GeoIP lookups and metadata.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Metadata about the GeoIP database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpMetadata {
    /// Source path or URL
    pub source: String,
    /// Database build date/version (extracted from database)
    pub version: String,
    /// Last update timestamp
    pub last_updated: SystemTime,
}

/// GeoIP lookup result
#[derive(Debug, Clone, Default)]
pub struct GeoIpResult {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub postal_code: Option<String>,
    pub timezone: Option<String>,
    pub asn: Option<u32>,
    pub asn_org: Option<String>,
}

