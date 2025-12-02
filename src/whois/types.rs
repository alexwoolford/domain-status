//! WHOIS data structures.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// WHOIS lookup result
#[derive(Debug, Clone, Default)]
pub struct WhoisResult {
    /// Domain creation date
    pub creation_date: Option<DateTime<Utc>>,
    /// Domain expiration date
    pub expiration_date: Option<DateTime<Utc>>,
    /// Domain updated date
    pub updated_date: Option<DateTime<Utc>>,
    /// Registrar name
    pub registrar: Option<String>,
    /// Registrant country code (ISO 3166-1 alpha-2)
    pub registrant_country: Option<String>,
    /// Registrant organization
    pub registrant_org: Option<String>,
    /// Domain status (e.g., "clientTransferProhibited")
    pub status: Option<Vec<String>>,
    /// Nameservers from WHOIS
    pub nameservers: Option<Vec<String>>,
    /// Raw WHOIS text (for debugging/fallback)
    pub raw_text: Option<String>,
}

/// Metadata about a cached WHOIS lookup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WhoisCacheEntry {
    pub(crate) result: WhoisCacheResult,
    pub(crate) cached_at: SystemTime,
    pub(crate) domain: String,
}

/// Serializable version of WhoisResult for caching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WhoisCacheResult {
    creation_date: Option<i64>,
    expiration_date: Option<i64>,
    updated_date: Option<i64>,
    registrar: Option<String>,
    registrant_country: Option<String>,
    registrant_org: Option<String>,
    status: Option<Vec<String>>,
    nameservers: Option<Vec<String>>,
    raw_text: Option<String>,
}

impl From<&WhoisResult> for WhoisCacheResult {
    fn from(result: &WhoisResult) -> Self {
        WhoisCacheResult {
            creation_date: result.creation_date.map(|dt| dt.timestamp_millis()),
            expiration_date: result.expiration_date.map(|dt| dt.timestamp_millis()),
            updated_date: result.updated_date.map(|dt| dt.timestamp_millis()),
            registrar: result.registrar.clone(),
            registrant_country: result.registrant_country.clone(),
            registrant_org: result.registrant_org.clone(),
            status: result.status.clone(),
            nameservers: result.nameservers.clone(),
            raw_text: result.raw_text.clone(),
        }
    }
}

impl From<WhoisCacheResult> for WhoisResult {
    fn from(cache: WhoisCacheResult) -> Self {
        WhoisResult {
            creation_date: cache.creation_date.map(|ms| {
                DateTime::from_timestamp(ms / 1000, ((ms % 1000) * 1_000_000) as u32)
                    .unwrap_or_default()
            }),
            expiration_date: cache.expiration_date.map(|ms| {
                DateTime::from_timestamp(ms / 1000, ((ms % 1000) * 1_000_000) as u32)
                    .unwrap_or_default()
            }),
            updated_date: cache.updated_date.map(|ms| {
                DateTime::from_timestamp(ms / 1000, ((ms % 1000) * 1_000_000) as u32)
                    .unwrap_or_default()
            }),
            registrar: cache.registrar,
            registrant_country: cache.registrant_country,
            registrant_org: cache.registrant_org,
            status: cache.status,
            nameservers: cache.nameservers,
            raw_text: cache.raw_text,
        }
    }
}

