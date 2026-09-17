//! IP address lookup functions.
//!
//! This module provides functions to look up IP addresses in the `GeoIP` databases
//! and retrieve metadata about the loaded databases.

use super::types::{GeoIpMetadata, GeoIpResult};
use crate::geoip::{GeoIpReaderCache, GEOIP_ASN_READER, GEOIP_CITY_READER};
use std::net::IpAddr;

/// Owned `GeoIP` service that can be instantiated in tests without relying on process-global state.
#[derive(Clone)]
pub struct GeoIpService {
    city_reader: GeoIpReaderCache,
    asn_reader: GeoIpReaderCache,
}

impl std::fmt::Debug for GeoIpService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeoIpService").finish_non_exhaustive()
    }
}

impl Default for GeoIpService {
    fn default() -> Self {
        Self {
            city_reader: std::sync::Arc::clone(&GEOIP_CITY_READER),
            asn_reader: std::sync::Arc::clone(&GEOIP_ASN_READER),
        }
    }
}

fn log_lock_poison(kind: &str, err: impl std::fmt::Display) {
    log::error!(
        "GeoIP {kind} database access failed due to lock poisoning (fatal error). \
        Please restart the application. Details: {err}"
    );
}

impl GeoIpService {
    /// Create an empty service with no `GeoIP` databases loaded.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            city_reader: std::sync::Arc::new(std::sync::RwLock::new(None)),
            asn_reader: std::sync::Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Looks up an IP address in the City and ASN databases.
    ///
    /// Returns `Some` when either database has a record. Invalid IP strings yield `None`.
    /// `is_enabled` remains City-loaded; this method does not require City data for ASN hits.
    #[must_use]
    pub fn lookup_ip(&self, ip: &str) -> Option<GeoIpResult> {
        let ip_addr: IpAddr = match ip.parse() {
            Ok(addr) => addr,
            Err(e) => {
                log::debug!("Failed to parse IP address '{ip}': {e}");
                return None;
            }
        };

        let mut geo_result = GeoIpResult::default();
        let city_hit = fill_city(&self.city_reader, ip_addr, &mut geo_result);
        let asn_hit = fill_asn(&self.asn_reader, ip_addr, &mut geo_result);
        (city_hit || asn_hit).then_some(geo_result)
    }

    /// Gets the current `GeoIP` City metadata if initialized.
    #[must_use]
    pub fn get_metadata(&self) -> Option<GeoIpMetadata> {
        let reader = self.city_reader.read().ok()?;
        reader.as_ref().map(|(_, metadata)| metadata.clone())
    }

    /// Checks if `GeoIP` is enabled (City database is loaded).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.city_reader
            .read()
            .ok()
            .and_then(|reader| reader.as_ref().map(|_| true))
            .unwrap_or(false)
    }
}

fn fill_city(cache: &GeoIpReaderCache, ip_addr: IpAddr, out: &mut GeoIpResult) -> bool {
    let guard = match cache.read() {
        Ok(guard) => guard,
        Err(e) => {
            log_lock_poison("City", e);
            return false;
        }
    };
    let Some((reader, _)) = guard.as_ref() else {
        return false;
    };
    let Ok(lookup) = reader.lookup(ip_addr) else {
        return false;
    };
    if !lookup.has_data() {
        return false;
    }
    let Ok(Some(city)) = lookup.decode::<maxminddb::geoip2::City>() else {
        return false;
    };

    out.country_code = city.country.iso_code.map(std::string::ToString::to_string);
    out.country_name = city
        .country
        .names
        .english
        .map(std::string::ToString::to_string);
    if let Some(subdivision) = city.subdivisions.first() {
        out.region = subdivision
            .names
            .english
            .map(std::string::ToString::to_string);
    }
    out.city = city
        .city
        .names
        .english
        .map(std::string::ToString::to_string);
    out.latitude = city.location.latitude;
    out.longitude = city.location.longitude;
    out.timezone = city
        .location
        .time_zone
        .map(std::string::ToString::to_string);
    out.postal_code = city.postal.code.map(std::string::ToString::to_string);
    true
}

fn fill_asn(cache: &GeoIpReaderCache, ip_addr: IpAddr, out: &mut GeoIpResult) -> bool {
    let guard = match cache.read() {
        Ok(guard) => guard,
        Err(e) => {
            log_lock_poison("ASN", e);
            return false;
        }
    };
    let Some((reader, _)) = guard.as_ref() else {
        return false;
    };
    let Ok(lookup) = reader.lookup(ip_addr) else {
        return false;
    };
    if !lookup.has_data() {
        return false;
    }
    let Ok(Some(asn)) = lookup.decode::<maxminddb::geoip2::Asn>() else {
        return false;
    };
    out.asn = asn.autonomous_system_number;
    out.asn_org = asn
        .autonomous_system_organization
        .map(std::string::ToString::to_string);
    true
}

/// Looks up an IP address using the default `GeoIP` service.
pub fn lookup_ip(ip: &str) -> Option<GeoIpResult> {
    GeoIpService::default().lookup_ip(ip)
}

/// Checks if `GeoIP` is enabled (database is loaded).
pub fn is_enabled() -> bool {
    GeoIpService::default().is_enabled()
}

#[cfg(test)]
impl GeoIpService {
    /// Constructor for a future synthetic-MMDB lookup suite (no production `GeoLite2` in tests).
    #[allow(dead_code)]
    pub(crate) fn from_readers(
        city: Option<std::sync::Arc<maxminddb::Reader<Vec<u8>>>>,
        asn: Option<std::sync::Arc<maxminddb::Reader<Vec<u8>>>>,
    ) -> Self {
        let placeholder = GeoIpMetadata {
            source: "test".to_string(),
            version: "test".to_string(),
            last_updated: std::time::SystemTime::UNIX_EPOCH,
        };
        let wrap = |reader: Option<std::sync::Arc<maxminddb::Reader<Vec<u8>>>>| {
            std::sync::Arc::new(std::sync::RwLock::new(
                reader.map(|r| (r, placeholder.clone())),
            ))
        };
        Self {
            city_reader: wrap(city),
            asn_reader: wrap(asn),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_service_reports_disabled() {
        let service = GeoIpService::empty();
        assert!(!service.is_enabled());
        assert!(service.get_metadata().is_none());
    }

    #[test]
    fn test_empty_service_returns_none_for_valid_ip() {
        let service = GeoIpService::empty();
        assert!(service.lookup_ip("8.8.8.8").is_none());
        assert!(service.lookup_ip("2001:4860:4860::8888").is_none());
    }

    #[test]
    fn test_lookup_ip_invalid_input_returns_none() {
        let service = GeoIpService::empty();
        for ip in [
            "",
            "   ",
            "not.an.ip",
            "1.2.3.4.5",
            "1.2.3",
            "256.1.1.1",
            "8.8.8.8\n",
            "8.8.8.8\t",
            " 8.8.8.8 ",
            "-1.0.0.0",
            "0xdead",
            "::g",
            "2001:db8::1%",
            "fe80::1%eth0",
        ] {
            assert!(
                service.lookup_ip(ip).is_none(),
                "expected None for invalid input {ip:?}"
            );
        }
    }
}
