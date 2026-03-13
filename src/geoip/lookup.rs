//! IP address lookup functions.
//!
//! This module provides functions to look up IP addresses in the `GeoIP` databases
//! and retrieve metadata about the loaded databases.

use super::types::{GeoIpMetadata, GeoIpResult};
use crate::geoip::{GeoIpReaderCache, GEOIP_ASN_READER, GEOIP_CITY_READER};

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

impl GeoIpService {
    /// Create an empty service with no `GeoIP` databases loaded.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            city_reader: std::sync::Arc::new(std::sync::RwLock::new(None)),
            asn_reader: std::sync::Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Looks up an IP address in the `GeoIP` databases (City and ASN).
    #[must_use]
    pub fn lookup_ip(&self, ip: &str) -> Option<GeoIpResult> {
        let city_reader = match self.city_reader.read() {
            Ok(reader) => reader,
            Err(e) => {
                log::error!(
                    "GeoIP database access failed due to lock poisoning (fatal error). \
                    Please restart the application. Details: {e}"
                );
                return None;
            }
        };
        let (city_reader, _) = city_reader.as_ref()?;

        let ip_addr: std::net::IpAddr = match ip.parse() {
            Ok(addr) => addr,
            Err(e) => {
                log::debug!("Failed to parse IP address '{ip}': {e}");
                return None;
            }
        };

        let mut geo_result = GeoIpResult::default();
        let Ok(city_lookup) = city_reader.lookup(ip_addr) else {
            return None;
        };
        if !city_lookup.has_data() {
            return None;
        }

        let city_result: maxminddb::geoip2::City = match city_lookup.decode() {
            Ok(Some(city)) => city,
            Ok(None) | Err(_) => return None,
        };

        geo_result.country_code = city_result
            .country
            .iso_code
            .map(std::string::ToString::to_string);
        geo_result.country_name = city_result
            .country
            .names
            .english
            .map(std::string::ToString::to_string);
        if let Some(subdivision) = city_result.subdivisions.first() {
            geo_result.region = subdivision
                .names
                .english
                .map(std::string::ToString::to_string);
        }
        geo_result.city = city_result
            .city
            .names
            .english
            .map(std::string::ToString::to_string);
        geo_result.latitude = city_result.location.latitude;
        geo_result.longitude = city_result.location.longitude;
        geo_result.timezone = city_result
            .location
            .time_zone
            .map(std::string::ToString::to_string);
        geo_result.postal_code = city_result
            .postal
            .code
            .map(std::string::ToString::to_string);

        let asn_reader = match self.asn_reader.read() {
            Ok(reader) => reader,
            Err(e) => {
                log::error!(
                    "GeoIP database access failed due to lock poisoning (fatal error). \
                    Please restart the application. Details: {e}"
                );
                return None;
            }
        };
        if let Some((asn_reader, _)) = asn_reader.as_ref() {
            if let Ok(asn_lookup) = asn_reader.lookup(ip_addr) {
                if asn_lookup.has_data() {
                    if let Ok(Some(asn_result)) = asn_lookup.decode::<maxminddb::geoip2::Asn>() {
                        geo_result.asn = asn_result.autonomous_system_number;
                        geo_result.asn_org = asn_result
                            .autonomous_system_organization
                            .map(std::string::ToString::to_string);
                    }
                }
            }
        }

        Some(geo_result)
    }

    /// Gets the current `GeoIP` City metadata if initialized.
    #[must_use]
    pub fn get_metadata(&self) -> Option<GeoIpMetadata> {
        let reader = self.city_reader.read().ok()?;
        reader.as_ref().map(|(_, metadata)| metadata.clone())
    }

    /// Checks if `GeoIP` is enabled (database is loaded).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.city_reader
            .read()
            .ok()
            .and_then(|reader| reader.as_ref().map(|_| true))
            .unwrap_or(false)
    }
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
mod tests {
    use super::*;

    #[test]
    fn test_empty_service_reports_disabled() {
        let service = GeoIpService::empty();
        assert!(!service.is_enabled());
        assert!(service.get_metadata().is_none());
    }

    #[test]
    fn test_empty_service_returns_none_for_valid_and_invalid_ips() {
        let service = GeoIpService::empty();
        assert!(service.lookup_ip("8.8.8.8").is_none());
        assert!(service.lookup_ip("not.an.ip.address").is_none());
        assert!(service.lookup_ip("").is_none());
    }

    #[test]
    fn test_empty_service_rejects_malformed_addresses() {
        let service = GeoIpService::empty();
        for ip in [
            "256.1.1.1",
            "1.1.1",
            "999.999.999.999",
            " 8.8.8.8 ",
            "8.8.8.8\0",
            "fe80::1%eth0",
        ] {
            assert!(service.lookup_ip(ip).is_none(), "expected None for {ip}");
        }
    }

    /// Boundary/adversarial: invalid or malformed IPs must return None without panic.
    #[test]
    fn test_lookup_ip_invalid_input_returns_none() {
        let service = GeoIpService::empty();
        let invalid = [
            "",
            "   ",
            "not.an.ip",
            "1.2.3.4.5",
            "1.2.3",
            "8.8.8.8\n",
            "8.8.8.8\t",
            "-1.0.0.0",
            "0xdead",
            "::g",
            "2001:db8::1%",
        ];
        for ip in invalid {
            assert!(
                service.lookup_ip(ip).is_none(),
                "expected None for invalid input {:?}",
                ip
            );
        }
    }

    #[test]
    fn test_default_wrapper_delegates_without_panicking() {
        let _ = lookup_ip("8.8.8.8");
        let _ = is_enabled();
        let _ = GeoIpService::default().get_metadata();
    }
}
