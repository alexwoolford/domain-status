//! Batch writer types and structures.
//!
//! This module defines the data structures used for batch writing operations.

use std::collections::HashMap;
use std::collections::HashSet;

use crate::geoip::GeoIpResult;
use crate::parse::{AnalyticsId, SocialMediaLink, StructuredData};
use crate::security::SecurityWarning;
use crate::whois::WhoisResult;

use crate::storage::models::{UrlPartialFailureRecord, UrlRecord};

/// Configuration for batch writing
#[derive(Clone)]
pub struct BatchConfig {
    /// Maximum number of records to batch before flushing
    pub batch_size: usize,
    /// Interval between automatic flushes (in seconds)
    pub flush_interval_secs: u64,
}

impl Default for BatchConfig {
    fn default() -> Self {
        BatchConfig {
            batch_size: 100,
            flush_interval_secs: 5,
        }
    }
}

/// Result of a batch flush operation.
///
/// Provides visibility into how many records were successfully inserted
/// and how many failed, enabling better observability and monitoring.
#[derive(Debug, Clone)]
pub struct FlushResult {
    /// Total number of records in the batch
    pub total: usize,
    /// Number of records successfully inserted
    pub successful: usize,
    /// Number of records that failed to insert
    pub failed: usize,
}

/// A complete record ready for batched insertion
pub struct BatchRecord {
    pub url_record: UrlRecord,
    pub security_headers: HashMap<String, String>,
    pub http_headers: HashMap<String, String>,
    pub oids: HashSet<String>,
    pub redirect_chain: Vec<String>,
    pub technologies: Vec<String>,
    pub subject_alternative_names: Vec<String>, // Certificate SANs (for linking domains sharing certificates)
    pub analytics_ids: Vec<AnalyticsId>, // Analytics/tracking IDs (GA, Facebook Pixel, GTM, AdSense)
    pub geoip: Option<(String, GeoIpResult)>,          // (ip_address, geoip_result)
    pub structured_data: Option<StructuredData>,
    pub social_media_links: Vec<SocialMediaLink>,
    pub security_warnings: Vec<SecurityWarning>,
    pub whois: Option<WhoisResult>,
    pub partial_failures: Vec<UrlPartialFailureRecord>, // DNS/TLS errors that didn't prevent processing
}

