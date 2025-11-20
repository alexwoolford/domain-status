// whois/mod.rs
// WHOIS/RDAP domain lookup using whois-service crate

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use whois_service::{WhoisClient, WhoisResponse};

/// Default cache directory for WHOIS data
const DEFAULT_CACHE_DIR: &str = ".whois_cache";

/// Default cache TTL: 7 days (WHOIS data changes infrequently)
const CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

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
struct WhoisCacheEntry {
    result: WhoisCacheResult,
    cached_at: SystemTime,
    domain: String,
}

/// Serializable version of WhoisResult for caching
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WhoisCacheResult {
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

/// Converts whois-service ParsedWhoisData to our WhoisResult
fn convert_parsed_data(response: &WhoisResponse) -> WhoisResult {
    let parsed = match &response.parsed_data {
        Some(p) => p,
        None => {
            // No parsed data, return minimal result with raw text
            return WhoisResult {
                raw_text: Some(response.raw_data.clone()),
                ..Default::default()
            };
        }
    };

    // Parse date strings to DateTime<Utc>
    let creation_date = parsed.creation_date.as_ref().and_then(|s| {
        parse_date_string(s).or_else(|| {
            // Try ISO 8601 format
            DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        })
    });

    let expiration_date = parsed.expiration_date.as_ref().and_then(|s| {
        parse_date_string(s).or_else(|| {
            DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        })
    });

    let updated_date = parsed.updated_date.as_ref().and_then(|s| {
        parse_date_string(s).or_else(|| {
            DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
        })
    });

    WhoisResult {
        creation_date,
        expiration_date,
        updated_date,
        registrar: parsed.registrar.clone(),
        registrant_country: None, // whois-service doesn't provide this directly
        registrant_org: parsed.registrant_name.clone(),
        status: if parsed.status.is_empty() {
            None
        } else {
            Some(parsed.status.clone())
        },
        nameservers: if parsed.name_servers.is_empty() {
            None
        } else {
            Some(parsed.name_servers.clone())
        },
        raw_text: Some(response.raw_data.clone()),
    }
}

/// Attempts to parse a date string in various formats
fn parse_date_string(date_str: &str) -> Option<DateTime<Utc>> {
    // Try common WHOIS date formats
    let formats = [
        "%Y-%m-%dT%H:%M:%S%.fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d-%b-%Y",
        "%d/%m/%Y",
    ];

    for format in &formats {
        if let Ok(dt) = DateTime::parse_from_str(date_str, format) {
            return Some(dt.with_timezone(&Utc));
        }
        if let Ok(naive_dt) = chrono::NaiveDateTime::parse_from_str(date_str, format) {
            return Some(naive_dt.and_utc());
        }
        if let Ok(naive_date) = chrono::NaiveDate::parse_from_str(date_str, format) {
            return Some(naive_date.and_hms_opt(0, 0, 0)?.and_utc());
        }
    }

    None
}

/// Loads a cached WHOIS result from disk
fn load_from_cache(cache_path: &Path, domain: &str) -> Result<Option<WhoisCacheEntry>> {
    let cache_file = cache_path.join(format!("{}.json", domain.replace('.', "_")));

    if !cache_file.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(&cache_file).context("Failed to read cache file")?;
    let entry: WhoisCacheEntry =
        serde_json::from_str(&content).context("Failed to parse cache file")?;

    // Check if cache is still valid
    let age = entry.cached_at.elapsed().unwrap_or_default();
    if age.as_secs() > CACHE_TTL_SECS {
        // Cache expired, delete it
        let _ = std::fs::remove_file(&cache_file);
        return Ok(None);
    }

    Ok(Some(entry))
}

/// Saves a WHOIS result to disk cache
fn save_to_cache(cache_path: &Path, domain: &str, result: &WhoisResult) -> Result<()> {
    std::fs::create_dir_all(cache_path).context("Failed to create cache directory")?;

    let cache_file = cache_path.join(format!("{}.json", domain.replace('.', "_")));
    let entry = WhoisCacheEntry {
        result: result.into(),
        cached_at: SystemTime::now(),
        domain: domain.to_string(),
    };

    let content =
        serde_json::to_string_pretty(&entry).context("Failed to serialize cache entry")?;
    std::fs::write(&cache_file, content).context("Failed to write cache file")?;

    Ok(())
}

/// Performs a WHOIS lookup for a domain
///
/// This function uses the `whois-service` crate which:
/// - Automatically tries RDAP first, then falls back to WHOIS
/// - Handles IANA bootstrap for TLD discovery
/// - Implements per-server rate limiting
/// - Provides structured parsing
///
/// # Arguments
///
/// * `domain` - The domain to look up (e.g., "example.com")
/// * `cache_dir` - Optional cache directory for storing WHOIS data
///
/// # Returns
///
/// Returns WHOIS information if available, or None if lookup fails
pub async fn lookup_whois(domain: &str, cache_dir: Option<&Path>) -> Result<Option<WhoisResult>> {
    let cache_path = cache_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CACHE_DIR));

    // Check cache first
    if let Some(cached) = load_from_cache(&cache_path, domain)? {
        log::debug!("WHOIS cache hit for {}", domain);
        return Ok(Some(cached.result.into()));
    }

    log::info!("Starting WHOIS lookup for domain: {}", domain);

    // Use whois-service client (create new instance each time since it's lightweight)
    let client = WhoisClient::new()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create WHOIS client: {}", e))?;
    match client.lookup(domain).await {
        Ok(response) => {
            log::info!("WHOIS lookup successful for {}", domain);
            let result = convert_parsed_data(&response);

            // Cache the result
            save_to_cache(&cache_path, domain, &result)?;

            Ok(Some(result))
        }
        Err(e) => {
            log::warn!("WHOIS lookup failed for {}: {}", domain, e);
            Ok(None)
        }
    }
}
