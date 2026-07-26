//! `GeoIP` lookup using `MaxMind` `GeoLite2` database.
//!
//! This module provides `GeoIP` lookup functionality using `MaxMind` `GeoLite2` databases.
//! It supports automatic downloading, caching, and lookup of IP addresses for
//! geographic and network information.

mod extract;
mod init;
mod lookup;
mod metadata;
mod types;

// Re-export public API
pub use init::init_geoip;
pub use lookup::{is_enabled, lookup_ip, GeoIpService};
pub use types::{GeoIpMetadata, GeoIpResult};

use maxminddb::Reader;
use std::sync::{Arc, LazyLock, RwLock};

/// Environment variable name for `MaxMind` license key
pub const MAXMIND_LICENSE_KEY_ENV: &str = "MAXMIND_LICENSE_KEY";

/// Cache TTL in seconds (7 days)
pub const CACHE_TTL_SECS: u64 = crate::config::GEOIP_CACHE_TTL_SECS;

/// `MaxMind` download base URL
pub const MAXMIND_DOWNLOAD_BASE: &str = "https://download.maxmind.com/app/geoip_download";

/// Type alias for `GeoIP` reader cache entry
type GeoIpReaderCache = Arc<RwLock<Option<(Arc<Reader<Vec<u8>>>, GeoIpMetadata)>>>;

/// Global `GeoIP` City reader cache (lazy-loaded)
/// Note: Reader owns the data, so we store the bytes separately
pub(crate) static GEOIP_CITY_READER: LazyLock<GeoIpReaderCache> =
    LazyLock::new(|| Arc::new(RwLock::new(None)));

/// Global `GeoIP` ASN reader cache (lazy-loaded)
/// ASN data requires a separate database (GeoLite2-ASN)
pub(crate) static GEOIP_ASN_READER: LazyLock<GeoIpReaderCache> =
    LazyLock::new(|| Arc::new(RwLock::new(None)));

/// Test helpers for serializing `MAXMIND_LICENSE_KEY` env mutations across parallel tests.
#[cfg(test)]
pub(crate) mod test_support {
    use super::MAXMIND_LICENSE_KEY_ENV;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Holds the license-key env lock; restores the previous value on drop.
    pub struct LicenseKeyEnvGuard {
        _lock: MutexGuard<'static, ()>,
        previous: Option<String>,
    }

    impl LicenseKeyEnvGuard {
        /// Acquire the lock and set `MAXMIND_LICENSE_KEY` (`None` clears it).
        pub fn apply(value: Option<&str>) -> Self {
            let lock = env_lock();
            let previous = std::env::var(MAXMIND_LICENSE_KEY_ENV).ok();
            match value {
                Some(v) => std::env::set_var(MAXMIND_LICENSE_KEY_ENV, v),
                None => std::env::remove_var(MAXMIND_LICENSE_KEY_ENV),
            }
            Self {
                _lock: lock,
                previous,
            }
        }
    }

    impl Drop for LicenseKeyEnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(v) => std::env::set_var(MAXMIND_LICENSE_KEY_ENV, v),
                None => std::env::remove_var(MAXMIND_LICENSE_KEY_ENV),
            }
        }
    }
}
