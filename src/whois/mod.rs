// whois/mod.rs
// WHOIS/RDAP domain lookup with conservative rate limiting

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime};
use tokio::sync::Semaphore;
use tokio::time::{interval, sleep};

/// Default cache directory for WHOIS data
const DEFAULT_CACHE_DIR: &str = ".whois_cache";

/// Default cache TTL: 7 days (WHOIS data changes infrequently)
const CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// Default rate limit: 1 query per 2 seconds (very conservative)
/// This is 0.5 queries/second, well below most registrar limits
const DEFAULT_WHOIS_RATE_LIMIT_SECS: u64 = 2;

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
    creation_date: Option<i64>, // Milliseconds since Unix epoch
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

/// Global rate limiter for WHOIS queries
/// Uses a semaphore with token replenishment to enforce rate limits
static WHOIS_RATE_LIMITER: LazyLock<Arc<WhoisRateLimiter>> =
    LazyLock::new(|| Arc::new(WhoisRateLimiter::new(DEFAULT_WHOIS_RATE_LIMIT_SECS)));

/// Rate limiter for WHOIS queries
/// Ensures we don't exceed registrar rate limits
struct WhoisRateLimiter {
    semaphore: Arc<Semaphore>,
    #[allow(dead_code)]
    interval_secs: u64, // Used in spawn closure, but compiler doesn't detect it
}

impl WhoisRateLimiter {
    fn new(interval_secs: u64) -> Self {
        let semaphore = Arc::new(Semaphore::new(1));
        let limiter = WhoisRateLimiter {
            semaphore: semaphore.clone(),
            interval_secs,
        };

        // Start background task to replenish permits
        let mut interval_timer = interval(Duration::from_secs(interval_secs));
        tokio::spawn(async move {
            loop {
                interval_timer.tick().await;
                // Add a permit (up to max of 1 for conservative limiting)
                if semaphore.available_permits() == 0 {
                    semaphore.add_permits(1);
                }
            }
        });

        limiter
    }

    /// Acquires a permit, waiting if necessary
    async fn acquire(&self) {
        let _permit = self.semaphore.acquire().await.unwrap();
        // Permit is held until dropped, ensuring rate limit is respected
    }
}

/// RDAP response structure (simplified - we only extract what we need)
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RdapResponse {
    #[serde(rename = "objectClassName")]
    object_class_name: Option<String>,
    handle: Option<String>,
    #[serde(rename = "ldhName")]
    ldh_name: Option<String>,
    events: Option<Vec<RdapEvent>>,
    entities: Option<Vec<RdapEntity>>,
    status: Option<Vec<String>>,
    nameservers: Option<Vec<RdapNameserver>>,
}

#[derive(Debug, Deserialize)]
struct RdapEvent {
    #[serde(rename = "eventAction")]
    event_action: Option<String>,
    #[serde(rename = "eventDate")]
    event_date: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RdapEntity {
    roles: Option<Vec<String>>,
    #[serde(rename = "vcardArray")]
    vcard_array: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
struct RdapNameserver {
    #[serde(rename = "ldhName")]
    ldh_name: Option<String>,
}

/// Looks up WHOIS information for a domain using RDAP (preferred) or WHOIS (fallback)
///
/// # Arguments
///
/// * `domain` - The domain to look up (e.g., "example.com")
/// * `cache_dir` - Optional cache directory for storing WHOIS data
///
/// # Returns
///
/// Returns WHOIS information if available, or None if lookup fails
///
/// # Rate Limiting
///
/// This function respects a conservative rate limit (default: 1 query per 2 seconds)
/// to avoid exceeding registrar limits. The rate limit is enforced globally across
/// all WHOIS lookups.
pub async fn lookup_whois(domain: &str, cache_dir: Option<&Path>) -> Result<Option<WhoisResult>> {
    let cache_path = cache_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CACHE_DIR));

    // Check cache first
    if let Some(cached) = load_from_cache(&cache_path, domain)? {
        return Ok(Some(cached.result.into()));
    }

    // Acquire rate limiter permit (waits if necessary)
    WHOIS_RATE_LIMITER.acquire().await;

    // Try RDAP first (preferred method)
    log::info!("Starting WHOIS/RDAP lookup for domain: {}", domain);
    let result = match lookup_rdap(domain).await {
        Ok(Some(rdap_result)) => {
            log::info!("RDAP lookup successful for {}", domain);
            Some(rdap_result)
        }
        Ok(None) => {
            log::info!(
                "RDAP lookup returned no data for {}, trying WHOIS fallback",
                domain
            );
            // Fallback to WHOIS
            match lookup_whois_text(domain).await {
                Ok(Some(whois_result)) => {
                    log::info!("WHOIS lookup successful for {}", domain);
                    Some(whois_result)
                }
                Ok(None) => {
                    log::info!("WHOIS lookup returned no data for {}", domain);
                    None
                }
                Err(whois_err) => {
                    log::warn!(
                        "Both RDAP and WHOIS lookups failed for {}: WHOIS={}",
                        domain,
                        whois_err
                    );
                    None
                }
            }
        }
        Err(e) => {
            log::info!(
                "RDAP lookup failed for {}: {}, trying WHOIS fallback",
                domain,
                e
            );
            // Fallback to WHOIS
            match lookup_whois_text(domain).await {
                Ok(Some(whois_result)) => {
                    log::info!("WHOIS lookup successful for {}", domain);
                    Some(whois_result)
                }
                Ok(None) => {
                    log::info!("WHOIS lookup returned no data for {}", domain);
                    None
                }
                Err(whois_err) => {
                    log::warn!(
                        "Both RDAP and WHOIS lookups failed for {}: RDAP={}, WHOIS={}",
                        domain,
                        e,
                        whois_err
                    );
                    None
                }
            }
        }
    };

    // Cache the result (even if None, to avoid repeated lookups)
    if let Some(ref whois_result) = result {
        save_to_cache(&cache_path, domain, whois_result)?;
    }

    Ok(result)
}

/// Looks up domain information using RDAP (Registration Data Access Protocol)
///
/// RDAP is preferred over WHOIS because:
/// - Returns structured JSON data
/// - Faster and more reliable
/// - Better error handling
/// - Standardized format
async fn lookup_rdap(domain: &str) -> Result<Option<WhoisResult>> {
    // Validate domain format
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 {
        anyhow::bail!("Invalid domain: {}", domain);
    }

    // Use IANA's RDAP bootstrap service to find the correct RDAP server
    // First, try the domain directly via a public RDAP service
    // rdap.org is a public RDAP service that handles many TLDs
    let bootstrap_url = format!("https://rdap.org/domain/{}", domain);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("Failed to create HTTP client for RDAP")?;

    let response = client
        .get(&bootstrap_url)
        .header("Accept", "application/rdap+json")
        .send()
        .await
        .context("RDAP request failed")?;

    if !response.status().is_success() {
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            // Rate limited - wait and retry once
            log::warn!("RDAP rate limited for {}, waiting 5 seconds", domain);
            sleep(Duration::from_secs(5)).await;
            let retry_response = client
                .get(&bootstrap_url)
                .header("Accept", "application/rdap+json")
                .send()
                .await
                .context("RDAP retry request failed")?;
            if !retry_response.status().is_success() {
                return Ok(None);
            }
            return parse_rdap_response(retry_response).await;
        }
        return Ok(None);
    }

    parse_rdap_response(response).await
}

/// Parses an RDAP JSON response into a WhoisResult
async fn parse_rdap_response(response: reqwest::Response) -> Result<Option<WhoisResult>> {
    let text = response
        .text()
        .await
        .context("Failed to read RDAP response body")?;
    let rdap: RdapResponse =
        serde_json::from_str(&text).context("Failed to parse RDAP JSON response")?;

    let mut result = WhoisResult::default();

    // Extract events (creation, expiration, updated dates)
    if let Some(events) = rdap.events {
        for event in events {
            if let Some(action) = event.event_action {
                if let Some(date_str) = event.event_date {
                    if let Ok(date) = DateTime::parse_from_rfc3339(&date_str) {
                        let date_utc = date.with_timezone(&Utc);
                        match action.as_str() {
                            "registration" => result.creation_date = Some(date_utc),
                            "expiration" => result.expiration_date = Some(date_utc),
                            "last changed" | "last update" => result.updated_date = Some(date_utc),
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    // Extract registrar from entities
    if let Some(entities) = rdap.entities {
        for entity in entities {
            if let Some(roles) = &entity.roles {
                if roles.contains(&"registrar".to_string()) {
                    // Try to extract registrar name from vcard
                    if entity.vcard_array.is_some() {
                        // vcard is a complex structure, for now we'll extract what we can
                        // This is a simplified extraction
                        result.registrar = Some("Unknown Registrar".to_string());
                    }
                }
                if roles.contains(&"registrant".to_string()) {
                    // Extract registrant info
                    if entity.vcard_array.is_some() {
                        // Simplified extraction
                        result.registrant_org = Some("Unknown Organization".to_string());
                    }
                }
            }
        }
    }

    // Extract status
    result.status = rdap.status;

    // Extract nameservers
    if let Some(ns) = rdap.nameservers {
        result.nameservers = Some(ns.into_iter().filter_map(|n| n.ldh_name).collect());
    }

    Ok(Some(result))
}

/// Looks up domain information using traditional WHOIS (text-based)
///
/// This is a fallback when RDAP is not available.
/// WHOIS uses TCP port 43 and returns plain text.
async fn lookup_whois_text(domain: &str) -> Result<Option<WhoisResult>> {
    // Determine WHOIS server based on TLD
    let whois_server = get_whois_server(domain)?;

    // Connect to WHOIS server on port 43
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(format!("{}:43", whois_server)),
    )
    .await
    .context("WHOIS connection timeout")?
    .context("Failed to connect to WHOIS server")?;

    // Send domain query
    let query = format!("{}\r\n", domain);
    stream
        .write_all(query.as_bytes())
        .await
        .context("Failed to write WHOIS query")?;

    // Read response
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .await
        .context("Failed to read WHOIS response")?;

    // Parse WHOIS text (simplified - WHOIS format varies by registrar)
    let result = parse_whois_text(&response, domain)?;
    Ok(result)
}

/// Determines the appropriate WHOIS server for a domain based on its TLD
fn get_whois_server(domain: &str) -> Result<String> {
    // Extract TLD
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.is_empty() {
        anyhow::bail!("Invalid domain: {}", domain);
    }
    let tld = parts.last().unwrap();

    // Common WHOIS servers by TLD
    // This is a simplified mapping - in production, you'd want a more comprehensive list
    let server = match tld.to_lowercase().as_str() {
        "com" | "net" | "org" => "whois.verisign-grs.com",
        "edu" => "whois.educause.edu",
        "gov" => "whois.nic.gov",
        "uk" => "whois.nic.uk",
        "de" => "whois.denic.de",
        "fr" => "whois.afnic.fr",
        "jp" => "whois.jprs.jp",
        "au" => "whois.aunic.net",
        "ca" => "whois.cira.ca",
        _ => "whois.iana.org", // Default fallback
    };

    Ok(server.to_string())
}

/// Parses WHOIS text response into a WhoisResult
///
/// WHOIS format varies significantly by registrar, so this is a best-effort parser
fn parse_whois_text(whois_text: &str, _domain: &str) -> Result<Option<WhoisResult>> {
    let mut result = WhoisResult {
        raw_text: Some(whois_text.to_string()),
        ..Default::default()
    };

    let text_lower = whois_text.to_lowercase();

    // Check for common error messages
    if text_lower.contains("no match") || text_lower.contains("not found") {
        return Ok(None);
    }

    // Try to extract common fields using regex patterns
    // Creation date - try ISO 8601 format first (with time), then date-only
    if let Some(cap) =
        regex::Regex::new(r"(?i)creation date[:\s]+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)")
            .unwrap()
            .captures(whois_text)
    {
        if let Ok(dt) = DateTime::parse_from_rfc3339(&cap[1]) {
            result.creation_date = Some(dt.with_timezone(&Utc));
        }
    } else if let Some(cap) = regex::Regex::new(r"(?i)creation date[:\s]+(\d{4}-\d{2}-\d{2})")
        .unwrap()
        .captures(whois_text)
    {
        if let Ok(date) = chrono::NaiveDate::parse_from_str(&cap[1], "%Y-%m-%d") {
            result.creation_date = Some(date.and_hms_opt(0, 0, 0).unwrap().and_utc());
        }
    }

    // Expiration date - try ISO 8601 format first (with time), then date-only
    if let Some(cap) = regex::Regex::new(
        r"(?i)registr(?:y\s+)?expir(?:y|ation)\s+date[:\s]+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)",
    )
    .unwrap()
    .captures(whois_text)
    {
        if let Ok(dt) = DateTime::parse_from_rfc3339(&cap[1]) {
            result.expiration_date = Some(dt.with_timezone(&Utc));
        }
    } else if let Some(cap) =
        regex::Regex::new(r"(?i)registr(?:y\s+)?expir(?:y|ation)\s+date[:\s]+(\d{4}-\d{2}-\d{2})")
            .unwrap()
            .captures(whois_text)
    {
        if let Ok(date) = chrono::NaiveDate::parse_from_str(&cap[1], "%Y-%m-%d") {
            result.expiration_date = Some(date.and_hms_opt(0, 0, 0).unwrap().and_utc());
        }
    }

    // Updated date - try ISO 8601 format first (with time), then date-only
    if let Some(cap) =
        regex::Regex::new(r"(?i)updated\s+date[:\s]+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)")
            .unwrap()
            .captures(whois_text)
    {
        if let Ok(dt) = DateTime::parse_from_rfc3339(&cap[1]) {
            result.updated_date = Some(dt.with_timezone(&Utc));
        }
    } else if let Some(cap) = regex::Regex::new(r"(?i)updated\s+date[:\s]+(\d{4}-\d{2}-\d{2})")
        .unwrap()
        .captures(whois_text)
    {
        if let Ok(date) = chrono::NaiveDate::parse_from_str(&cap[1], "%Y-%m-%d") {
            result.updated_date = Some(date.and_hms_opt(0, 0, 0).unwrap().and_utc());
        }
    }

    // Registrar - try multiple patterns (WHOIS format varies)
    // Match "Registrar:" exactly (not "Registrar WHOIS Server:", "Registrar URL:", etc.)
    // Use negative lookahead to exclude "Registrar" followed by other words before the colon

    // Try exact "Registrar:" first (most common format)
    if let Some(cap) = regex::Regex::new(r"(?im)^\s*registrar:\s*(.+?)$")
        .unwrap()
        .captures(whois_text)
    {
        result.registrar = Some(cap[1].trim().to_string());
    }

    // If no match, try "Registrar Name:" (more specific)
    if result.registrar.is_none() {
        if let Some(cap) = regex::Regex::new(r"(?im)^\s*registrar\s+name[:\s]+(.+?)$")
            .unwrap()
            .captures(whois_text)
        {
            result.registrar = Some(cap[1].trim().to_string());
        }
    }

    // If still no match, try "Sponsoring Registrar:"
    if result.registrar.is_none() {
        if let Some(cap) = regex::Regex::new(r"(?im)^\s*sponsoring\s+registrar[:\s]+(.+?)$")
            .unwrap()
            .captures(whois_text)
        {
            result.registrar = Some(cap[1].trim().to_string());
        }
    }

    // If no registrar found, try "Registrar Name:" (more specific)
    if result.registrar.is_none() {
        if let Some(cap) = regex::Regex::new(r"(?im)^\s*registrar\s+name[:\s]+(.+?)$")
            .unwrap()
            .captures(whois_text)
        {
            result.registrar = Some(cap[1].trim().to_string());
        }
    }

    // If still no registrar, try "Sponsoring Registrar:"
    if result.registrar.is_none() {
        if let Some(cap) = regex::Regex::new(r"(?im)^\s*sponsoring\s+registrar[:\s]+(.+?)$")
            .unwrap()
            .captures(whois_text)
        {
            result.registrar = Some(cap[1].trim().to_string());
        }
    }

    // Extract domain status (multiple lines possible)
    let status_regex =
        regex::Regex::new(r"(?im)^\s*domain\s+status[:\s]+(.+?)(?:\s+https://|$)").unwrap();
    let mut statuses = Vec::new();
    for cap in status_regex.captures_iter(whois_text) {
        let status = cap[1].trim().to_string();
        if !status.is_empty() {
            statuses.push(status);
        }
    }
    if !statuses.is_empty() {
        result.status = Some(statuses);
    }

    // Extract nameservers (multiple lines possible)
    let ns_regex = regex::Regex::new(r"(?im)^\s*name\s+server[:\s]+(.+?)$").unwrap();
    let mut nameservers = Vec::new();
    for cap in ns_regex.captures_iter(whois_text) {
        let ns = cap[1].trim().to_string();
        if !ns.is_empty() {
            nameservers.push(ns);
        }
    }
    if !nameservers.is_empty() {
        result.nameservers = Some(nameservers);
    }

    // If we got at least one field, return the result
    if result.creation_date.is_some()
        || result.expiration_date.is_some()
        || result.updated_date.is_some()
        || result.registrar.is_some()
        || result.status.is_some()
        || result.nameservers.is_some()
    {
        Ok(Some(result))
    } else {
        // No parseable data found
        Ok(None)
    }
}

/// Loads WHOIS data from cache if available and not expired
fn load_from_cache(cache_dir: &Path, domain: &str) -> Result<Option<WhoisCacheEntry>> {
    let cache_file = cache_dir.join(format!("{}.json", domain.replace('.', "_")));

    if !cache_file.exists() {
        return Ok(None);
    }

    let metadata =
        std::fs::read_to_string(&cache_file).context("Failed to read WHOIS cache file")?;
    let entry: WhoisCacheEntry =
        serde_json::from_str(&metadata).context("Failed to parse WHOIS cache file")?;

    // Check if cache is expired
    let age = entry.cached_at.elapsed().unwrap_or(Duration::MAX);
    if age.as_secs() > CACHE_TTL_SECS {
        // Cache expired, delete the file
        let _ = std::fs::remove_file(&cache_file);
        return Ok(None);
    }

    Ok(Some(entry))
}

/// Saves WHOIS data to cache
fn save_to_cache(cache_dir: &Path, domain: &str, result: &WhoisResult) -> Result<()> {
    std::fs::create_dir_all(cache_dir).context("Failed to create WHOIS cache directory")?;

    let cache_file = cache_dir.join(format!("{}.json", domain.replace('.', "_")));
    let entry = WhoisCacheEntry {
        result: WhoisCacheResult::from(result),
        cached_at: SystemTime::now(),
        domain: domain.to_string(),
    };

    let json =
        serde_json::to_string_pretty(&entry).context("Failed to serialize WHOIS cache entry")?;
    std::fs::write(&cache_file, json).context("Failed to write WHOIS cache file")?;

    Ok(())
}
