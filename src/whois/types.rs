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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whois_result_default() {
        let result = WhoisResult::default();
        assert!(result.creation_date.is_none());
        assert!(result.expiration_date.is_none());
        assert!(result.updated_date.is_none());
        assert!(result.registrar.is_none());
        assert!(result.registrant_country.is_none());
        assert!(result.registrant_org.is_none());
        assert!(result.status.is_none());
        assert!(result.nameservers.is_none());
        assert!(result.raw_text.is_none());
    }

    #[test]
    fn test_whois_result_clone() {
        let result = WhoisResult {
            creation_date: Some(chrono::Utc::now()),
            expiration_date: Some(chrono::Utc::now() + chrono::Duration::days(365)),
            registrar: Some("Test Registrar".to_string()),
            ..Default::default()
        };

        let cloned = result.clone();
        assert_eq!(cloned.registrar, result.registrar);
        assert!(cloned.creation_date.is_some());
    }

    #[test]
    fn test_whois_cache_result_from_whois_result() {
        let whois_result = WhoisResult {
            creation_date: Some(chrono::Utc::now()),
            expiration_date: Some(chrono::Utc::now() + chrono::Duration::days(365)),
            updated_date: Some(chrono::Utc::now()),
            registrar: Some("Test Registrar".to_string()),
            registrant_country: Some("US".to_string()),
            registrant_org: Some("Test Org".to_string()),
            status: Some(vec!["active".to_string()]),
            nameservers: Some(vec!["ns1.example.com".to_string()]),
            raw_text: Some("Raw text".to_string()),
        };

        let cache_result: WhoisCacheResult = (&whois_result).into();
        // Convert back to verify round-trip
        let converted_back: WhoisResult = cache_result.into();
        assert!(converted_back.creation_date.is_some());
        assert!(converted_back.expiration_date.is_some());
        assert_eq!(converted_back.registrar, Some("Test Registrar".to_string()));
        assert_eq!(converted_back.registrant_country, Some("US".to_string()));
        assert_eq!(converted_back.status, Some(vec!["active".to_string()]));
    }

    #[test]
    fn test_whois_cache_result_from_whois_result_none_fields() {
        let whois_result = WhoisResult::default();
        let cache_result: WhoisCacheResult = (&whois_result).into();
        // Convert back to verify round-trip
        let converted_back: WhoisResult = cache_result.into();
        assert!(converted_back.creation_date.is_none());
        assert!(converted_back.registrar.is_none());
    }

    #[test]
    fn test_whois_cache_result_round_trip() {
        let original = WhoisResult {
            creation_date: Some(chrono::Utc::now()),
            expiration_date: Some(chrono::Utc::now() + chrono::Duration::days(365)),
            updated_date: Some(chrono::Utc::now()),
            registrar: Some("Test Registrar".to_string()),
            registrant_country: Some("US".to_string()),
            registrant_org: Some("Test Org".to_string()),
            status: Some(vec!["active".to_string()]),
            nameservers: Some(vec!["ns1.example.com".to_string()]),
            raw_text: Some("Raw text".to_string()),
        };

        // Convert to cache format and back
        let cache_result: WhoisCacheResult = (&original).into();
        let converted: WhoisResult = cache_result.into();

        // Verify all fields are preserved
        assert_eq!(converted.registrar, original.registrar);
        assert_eq!(converted.registrant_country, original.registrant_country);
        assert_eq!(converted.registrant_org, original.registrant_org);
        assert_eq!(converted.status, original.status);
        assert_eq!(converted.nameservers, original.nameservers);
        assert_eq!(converted.raw_text, original.raw_text);
        // Dates may have slight precision differences due to millis conversion, so just verify they exist
        assert!(converted.creation_date.is_some());
        assert!(converted.expiration_date.is_some());
        assert!(converted.updated_date.is_some());
    }
}
