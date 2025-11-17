// geoip/mod.rs
// GeoIP lookup using MaxMind GeoLite2 database

use anyhow::{Context, Result};
use maxminddb::Reader;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, SystemTime};
use url::form_urlencoded;

/// Default cache directory for GeoIP database
const DEFAULT_CACHE_DIR: &str = ".geoip_cache";

/// Default cache TTL: 7 days (GeoIP databases are updated weekly)
const CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// MaxMind GeoLite2 download base URL
const MAXMIND_DOWNLOAD_BASE: &str = "https://download.maxmind.com/app/geoip_download";

/// Environment variable name for MaxMind license key
const MAXMIND_LICENSE_KEY_ENV: &str = "MAXMIND_LICENSE_KEY";

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

/// Global GeoIP City reader cache (lazy-loaded)
/// Note: Reader owns the data, so we store the bytes separately
static GEOIP_CITY_READER: LazyLock<Arc<RwLock<Option<(Arc<Reader<Vec<u8>>>, GeoIpMetadata)>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(None)));

/// Global GeoIP ASN reader cache (lazy-loaded)
/// ASN data requires a separate database (GeoLite2-ASN)
static GEOIP_ASN_READER: LazyLock<Arc<RwLock<Option<(Arc<Reader<Vec<u8>>>, GeoIpMetadata)>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(None)));

/// Initializes the GeoIP database from a local file path or automatic download.
///
/// The database is cached in memory and can be refreshed by calling this function
/// again with a different path or after the cache expires.
///
/// # Arguments
///
/// * `geoip_path` - Optional path to the MaxMind GeoLite2 database file (.mmdb) or download URL.
///                  If None, will attempt automatic download using MAXMIND_LICENSE_KEY env var.
/// * `cache_dir` - Optional cache directory for downloaded databases
///
/// # Returns
///
/// Returns the metadata about the loaded database, including version information.
///
/// # Automatic Download
///
/// If `geoip_path` is None but `MAXMIND_LICENSE_KEY` environment variable is set,
/// the function will automatically download the latest GeoLite2-City database.
pub async fn init_geoip(
    geoip_path: Option<&str>,
    cache_dir: Option<&Path>,
) -> Result<Option<GeoIpMetadata>> {
    let cache_path = cache_dir
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CACHE_DIR));

    // Determine the source path
    let path = match geoip_path {
        Some(p) => p.to_string(),
        None => {
            // Try automatic download if license key is available
            if let Ok(license_key) = std::env::var(MAXMIND_LICENSE_KEY_ENV) {
                if !license_key.is_empty() {
                    // Check cache first
                    let cache_file = cache_path.join("GeoLite2-City.mmdb");
                    let metadata_file = cache_path.join("metadata.json");

                    // Check if cached version exists and is fresh
                    let should_download = if let Ok(metadata) = load_metadata(&metadata_file).await
                    {
                        if let Ok(age) = metadata.last_updated.elapsed() {
                            age.as_secs() >= CACHE_TTL_SECS || !cache_file.exists()
                        } else {
                            true
                        }
                    } else {
                        true
                    };

                    if should_download {
                        log::info!(
                            "Auto-downloading GeoLite2-City database (cache expired or missing)"
                        );
                        // URL-encode the license key to handle special characters
                        let encoded_key = form_urlencoded::byte_serialize(license_key.as_bytes())
                            .collect::<String>();
                        let download_url = format!(
                            "{}?edition_id=GeoLite2-City&license_key={}&suffix=tar.gz",
                            MAXMIND_DOWNLOAD_BASE, encoded_key
                        );
                        download_url
                    } else {
                        // Use cached file
                        log::info!("Using cached GeoIP database");
                        cache_file.to_string_lossy().to_string()
                    }
                } else {
                    log::info!("GeoIP lookup disabled (no database path provided and MAXMIND_LICENSE_KEY is empty)");
                    return Ok(None);
                }
            } else {
                log::info!("GeoIP lookup disabled (no database path provided and MAXMIND_LICENSE_KEY not set)");
                return Ok(None);
            }
        }
    };

    // Check if City database already loaded
    {
        let reader = GEOIP_CITY_READER.read().unwrap();
        if let Some((_, ref metadata)) = *reader {
            // Check if source matches
            if metadata.source == path {
                log::info!("GeoIP City database already loaded: {}", path);
                // Still try to load ASN database if not already loaded
                init_asn_database(&cache_path).await?;
                return Ok(Some(metadata.clone()));
            }
        }
    }

    // Load City database (from local file, or download from URL)
    let (reader, metadata) = if path.starts_with("http://") || path.starts_with("https://") {
        // Download and cache (handles tar.gz extraction)
        load_from_url(&path, &cache_path, "GeoLite2-City").await?
    } else {
        // Load from local file
        load_from_file(&path).await?
    };

    let reader_arc = Arc::new(reader);
    *GEOIP_CITY_READER.write().unwrap() = Some((reader_arc, metadata.clone()));

    log::info!(
        "GeoIP City database loaded: {} (version: {})",
        metadata.source,
        metadata.version
    );

    // Also initialize ASN database if license key is available
    init_asn_database(&cache_path).await?;

    Ok(Some(metadata))
}

/// Initializes the GeoLite2-ASN database for ASN lookups.
async fn init_asn_database(cache_dir: &Path) -> Result<()> {
    // Check if ASN database already loaded
    {
        let reader = GEOIP_ASN_READER.read().unwrap();
        if reader.is_some() {
            return Ok(()); // Already loaded
        }
    }

    // Try to get license key for auto-download
    if let Ok(license_key) = std::env::var(MAXMIND_LICENSE_KEY_ENV) {
        if !license_key.is_empty() {
            let cache_file = cache_dir.join("GeoLite2-ASN.mmdb");
            let metadata_file = cache_dir.join("asn_metadata.json");

            // Check if cached version exists and is fresh
            let should_download = if let Ok(metadata) = load_metadata(&metadata_file).await {
                if let Ok(age) = metadata.last_updated.elapsed() {
                    age.as_secs() >= CACHE_TTL_SECS || !cache_file.exists()
                } else {
                    true
                }
            } else {
                true
            };

            if should_download {
                log::info!("Auto-downloading GeoLite2-ASN database (cache expired or missing)");
                let encoded_key =
                    form_urlencoded::byte_serialize(license_key.as_bytes()).collect::<String>();
                let download_url = format!(
                    "{}?edition_id=GeoLite2-ASN&license_key={}&suffix=tar.gz",
                    MAXMIND_DOWNLOAD_BASE, encoded_key
                );

                match load_from_url(&download_url, cache_dir, "GeoLite2-ASN").await {
                    Ok((reader, metadata)) => {
                        let reader_arc = Arc::new(reader);
                        *GEOIP_ASN_READER.write().unwrap() = Some((reader_arc, metadata));
                        log::info!("GeoIP ASN database loaded successfully");
                    }
                    Err(e) => {
                        log::warn!(
                            "Failed to load ASN database: {}. Continuing without ASN lookups.",
                            e
                        );
                    }
                }
            } else {
                // Load from cache
                if cache_file.exists() {
                    if let Ok((reader, metadata)) =
                        load_from_file(cache_file.to_str().unwrap()).await
                    {
                        let reader_arc = Arc::new(reader);
                        *GEOIP_ASN_READER.write().unwrap() = Some((reader_arc, metadata));
                        log::info!("GeoIP ASN database loaded from cache");
                    }
                }
            }
        }
    }

    Ok(())
}

/// Loads GeoIP database from a local file path
async fn load_from_file(path: &str) -> Result<(Reader<Vec<u8>>, GeoIpMetadata)> {
    log::info!("Loading GeoIP database from: {}", path);

    let db_bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("Failed to read GeoIP database from {}", path))?;

    // Create reader from owned bytes
    let reader = Reader::from_source(db_bytes.clone())
        .with_context(|| format!("Failed to parse GeoIP database from {}", path))?;

    // Extract metadata from database
    let metadata = extract_metadata(&reader, path)?;

    // Create reader with owned data
    let reader_owned = Reader::from_source(db_bytes)
        .with_context(|| format!("Failed to create owned reader from {}", path))?;

    Ok((reader_owned, metadata))
}

/// Downloads GeoIP database from URL and caches it locally.
///
/// Handles both direct .mmdb file downloads and tar.gz archives (MaxMind format).
///
/// # Arguments
///
/// * `url` - Download URL
/// * `cache_dir` - Cache directory
/// * `db_name` - Database name for cache file (e.g., "GeoLite2-City" or "GeoLite2-ASN")
async fn load_from_url(
    url: &str,
    cache_dir: &Path,
    db_name: &str,
) -> Result<(Reader<Vec<u8>>, GeoIpMetadata)> {
    // Create cache directory if it doesn't exist
    tokio::fs::create_dir_all(cache_dir)
        .await
        .with_context(|| format!("Failed to create cache directory: {:?}", cache_dir))?;

    let cache_file = cache_dir.join(format!("{}.mmdb", db_name));
    let metadata_file = cache_dir.join(format!("{}_metadata.json", db_name.to_lowercase()));

    // Check if cached version exists and is fresh
    if let Ok(metadata) = load_metadata(&metadata_file).await {
        if let Ok(age) = metadata.last_updated.elapsed() {
            if age.as_secs() < CACHE_TTL_SECS {
                // Cache is fresh, try to load
                if cache_file.exists() {
                    if let Ok((reader, _)) = load_from_file(cache_file.to_str().unwrap()).await {
                        log::info!("Loaded GeoIP database from cache: {:?}", cache_file);
                        return Ok((reader, metadata));
                    }
                }
            }
        }
    }

    // Download database
    log::info!("Downloading GeoIP database from: {}", url);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(300)) // 5 minutes for large file
        .build()?;

    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let error_body = response
            .text()
            .await
            .unwrap_or_else(|_| "No error details".to_string());
        log::error!("MaxMind API error response: {}", error_body);
        return Err(anyhow::anyhow!(
            "Failed to download GeoIP database: {} - {}",
            status,
            error_body
        ));
    }

    let downloaded_bytes = response.bytes().await?.to_vec();

    // Extract .mmdb file from tar.gz if needed, or use directly if it's already .mmdb
    let db_bytes = if url.ends_with(".tar.gz") || url.contains("suffix=tar.gz") {
        extract_mmdb_from_tar_gz(&downloaded_bytes, db_name)?
    } else if url.ends_with(".mmdb") {
        // Direct .mmdb file download
        downloaded_bytes
    } else {
        // Try to detect format - if it looks like tar.gz, extract it
        if downloaded_bytes.len() > 2 && downloaded_bytes[0] == 0x1f && downloaded_bytes[1] == 0x8b
        {
            // Gzip magic number
            extract_mmdb_from_tar_gz(&downloaded_bytes, db_name)?
        } else {
            // Assume it's already a .mmdb file
            downloaded_bytes
        }
    };

    // Save to cache
    tokio::fs::write(&cache_file, &db_bytes)
        .await
        .with_context(|| format!("Failed to write cache file: {:?}", cache_file))?;

    // Parse database to extract metadata (temporary reader for metadata extraction)
    let reader_temp = Reader::from_source(db_bytes.as_slice())
        .with_context(|| "Failed to parse downloaded GeoIP database")?;

    let metadata = extract_metadata(&reader_temp, url)?;

    // Create reader with owned data
    let reader = Reader::from_source(db_bytes)
        .with_context(|| "Failed to create owned reader from downloaded database")?;

    // Save metadata
    save_metadata(&metadata, &metadata_file).await?;

    Ok((reader, metadata))
}

/// Extracts .mmdb file from a tar.gz archive.
///
/// # Arguments
///
/// * `tar_gz_bytes` - The tar.gz archive bytes
/// * `db_name` - The database name to look for (e.g., "GeoLite2-City" or "GeoLite2-ASN")
fn extract_mmdb_from_tar_gz(tar_gz_bytes: &[u8], db_name: &str) -> Result<Vec<u8>> {
    use flate2::read::GzDecoder;
    use std::io::Read;
    use tar::Archive;

    log::debug!("Extracting .mmdb file from tar.gz archive");

    // Decompress gzip
    let gz_decoder = GzDecoder::new(tar_gz_bytes);
    let mut tar_archive = Archive::new(gz_decoder);

    // Extract entries
    let entries = tar_archive
        .entries()
        .with_context(|| "Failed to read tar archive entries")?;

    for entry_result in entries {
        let mut entry = entry_result.with_context(|| "Failed to read tar entry")?;
        let path = entry.path().with_context(|| "Failed to get entry path")?;

        // Look for the specified database .mmdb file
        if let Some(file_name) = path.file_name() {
            let expected_name = format!("{}.mmdb", db_name);
            if file_name.to_str() == Some(&expected_name) {
                let mut mmdb_bytes = Vec::new();
                entry.read_to_end(&mut mmdb_bytes).with_context(|| {
                    format!("Failed to read {}.mmdb file from archive", db_name)
                })?;
                log::info!(
                    "Extracted {}.mmdb from tar.gz ({} bytes)",
                    db_name,
                    mmdb_bytes.len()
                );
                return Ok(mmdb_bytes);
            }
        }
    }

    Err(anyhow::anyhow!(
        "{}.mmdb not found in tar.gz archive",
        db_name
    ))
}

/// Extracts metadata from a GeoIP database
fn extract_metadata<T: AsRef<[u8]>>(reader: &Reader<T>, source: &str) -> Result<GeoIpMetadata> {
    // Try to get build epoch from database metadata
    // MaxMind databases have a build_epoch field in their metadata
    let version = format!("build_{}", reader.metadata.build_epoch);

    Ok(GeoIpMetadata {
        source: source.to_string(),
        version,
        last_updated: SystemTime::now(),
    })
}

/// Loads metadata from cache file
async fn load_metadata(metadata_file: &Path) -> Result<GeoIpMetadata> {
    let content = tokio::fs::read_to_string(metadata_file).await?;
    let metadata: GeoIpMetadata = serde_json::from_str(&content)?;
    Ok(metadata)
}

/// Saves metadata to cache file
async fn save_metadata(metadata: &GeoIpMetadata, metadata_file: &Path) -> Result<()> {
    let content = serde_json::to_string_pretty(metadata)?;
    tokio::fs::write(metadata_file, content).await?;
    Ok(())
}

/// Looks up an IP address in the GeoIP databases (City and ASN).
///
/// Returns `None` if GeoIP is not initialized or if the lookup fails.
pub fn lookup_ip(ip: &str) -> Option<GeoIpResult> {
    let city_reader = GEOIP_CITY_READER.read().unwrap();
    let (city_reader, _) = city_reader.as_ref()?;

    // Parse IP address
    let ip_addr: std::net::IpAddr = ip.parse().ok()?;

    let mut geo_result = GeoIpResult::default();

    // Lookup in City database
    let city_result: maxminddb::geoip2::City = match city_reader.lookup(ip_addr) {
        Ok(city) => city,
        Err(_) => return None,
    };

    // Extract country information
    if let Some(country) = city_result.country {
        geo_result.country_code = country.iso_code.map(|s| s.to_string());
        if let Some(names) = country.names {
            geo_result.country_name = names.get("en").map(|s| s.to_string());
        }
    }

    // Extract subdivision (region/state)
    if let Some(subdivisions) = city_result.subdivisions {
        if let Some(subdivision) = subdivisions.first() {
            if let Some(names) = &subdivision.names {
                geo_result.region = names.get("en").map(|s| s.to_string());
            }
        }
    }

    // Extract city
    if let Some(city) = city_result.city {
        if let Some(names) = city.names {
            geo_result.city = names.get("en").map(|s| s.to_string());
        }
    }

    // Extract location (lat/lon)
    if let Some(location) = city_result.location {
        geo_result.latitude = location.latitude;
        geo_result.longitude = location.longitude;
        geo_result.timezone = location.time_zone.map(|s| s.to_string());
    }

    // Extract postal code (from postal field, not location)
    if let Some(postal) = city_result.postal {
        geo_result.postal_code = postal.code.map(|s| s.to_string());
    }

    // Lookup ASN data if ASN database is available
    let asn_reader = GEOIP_ASN_READER.read().unwrap();
    if let Some((asn_reader, _)) = asn_reader.as_ref() {
        if let Ok(asn_result) = asn_reader.lookup::<maxminddb::geoip2::Asn>(ip_addr) {
            geo_result.asn = asn_result.autonomous_system_number;
            geo_result.asn_org = asn_result
                .autonomous_system_organization
                .map(|s| s.to_string());
        }
    }

    Some(geo_result)
}

/// Gets the current GeoIP City metadata if initialized
#[allow(dead_code)]
pub fn get_metadata() -> Option<GeoIpMetadata> {
    let reader = GEOIP_CITY_READER.read().unwrap();
    reader.as_ref().map(|(_, metadata)| metadata.clone())
}
