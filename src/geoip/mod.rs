//! GeoIP lookup using MaxMind GeoLite2 database.
//!
//! This module provides GeoIP lookup functionality using MaxMind GeoLite2 databases.
//! It supports automatic downloading, caching, and lookup of IP addresses for
//! geographic and network information.

mod extract;
mod init;
mod lookup;
mod metadata;
mod types;

// Re-export public API
pub use init::init_geoip;
pub use lookup::lookup_ip;
pub use types::{GeoIpMetadata, GeoIpResult};

use maxminddb::Reader;
use std::sync::{Arc, LazyLock, RwLock};

/// Default cache directory for GeoIP databases
pub const DEFAULT_CACHE_DIR: &str = ".geoip_cache";

/// Environment variable name for MaxMind license key
pub const MAXMIND_LICENSE_KEY_ENV: &str = "MAXMIND_LICENSE_KEY";

/// Cache TTL in seconds (7 days)
pub const CACHE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

/// MaxMind download base URL
pub const MAXMIND_DOWNLOAD_BASE: &str = "https://download.maxmind.com/app/geoip_download";

/// Type alias for GeoIP reader cache entry
type GeoIpReaderCache = Arc<RwLock<Option<(Arc<Reader<Vec<u8>>>, GeoIpMetadata)>>>;

/// Global GeoIP City reader cache (lazy-loaded)
/// Note: Reader owns the data, so we store the bytes separately
pub(crate) static GEOIP_CITY_READER: LazyLock<GeoIpReaderCache> =
    LazyLock::new(|| Arc::new(RwLock::new(None)));

/// Global GeoIP ASN reader cache (lazy-loaded)
/// ASN data requires a separate database (GeoLite2-ASN)
pub(crate) static GEOIP_ASN_READER: LazyLock<GeoIpReaderCache> = LazyLock::new(|| Arc::new(RwLock::new(None)));
