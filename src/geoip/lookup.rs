//! IP address lookup functions.
//!
//! This module provides functions to look up IP addresses in the GeoIP databases
//! and retrieve metadata about the loaded databases.

use super::types::{GeoIpMetadata, GeoIpResult};
use crate::geoip::{GEOIP_ASN_READER, GEOIP_CITY_READER};

/// Looks up an IP address in the GeoIP databases (City and ASN).
///
/// Returns `None` if GeoIP is not initialized or if the lookup fails.
pub fn lookup_ip(ip: &str) -> Option<GeoIpResult> {
    let city_reader = GEOIP_CITY_READER.read().ok()?;
    let (city_reader, _) = city_reader.as_ref()?;

    // Parse IP address
    let ip_addr: std::net::IpAddr = ip.parse().ok()?;

    let mut geo_result = GeoIpResult::default();

    // Lookup in City database
    // maxminddb 0.27 API: lookup() returns Result<LookupResult, MaxMindDbError>
    // Use has_data() to check if data exists, then decode() to get the City struct
    let city_lookup = match city_reader.lookup(ip_addr) {
        Ok(result) => result,
        Err(_) => return None,
    };

    if !city_lookup.has_data() {
        return None;
    }

    let city_result: maxminddb::geoip2::City = match city_lookup.decode() {
        Ok(Some(city)) => city,
        Ok(None) => return None,
        Err(_) => return None,
    };

    // Extract country information
    // In maxminddb 0.27, fields are direct types (not Option), but inner fields may be Option
    // Names struct has fields like english, german, etc. (not a get() method)
    geo_result.country_code = city_result.country.iso_code.map(|s| s.to_string());
    geo_result.country_name = city_result.country.names.english.map(|s| s.to_string());

    // Extract subdivision (region/state)
    if !city_result.subdivisions.is_empty() {
        if let Some(subdivision) = city_result.subdivisions.first() {
            geo_result.region = subdivision.names.english.map(|s| s.to_string());
        }
    }

    // Extract city
    geo_result.city = city_result.city.names.english.map(|s| s.to_string());

    // Extract location (lat/lon)
    geo_result.latitude = city_result.location.latitude;
    geo_result.longitude = city_result.location.longitude;
    geo_result.timezone = city_result.location.time_zone.map(|s| s.to_string());

    // Extract postal code (from postal field, not location)
    geo_result.postal_code = city_result.postal.code.map(|s| s.to_string());

    // Lookup ASN data if ASN database is available
    // maxminddb 0.27 API: lookup() returns Result<LookupResult, MaxMindDbError>
    // Use has_data() to check if data exists, then decode() to get the Asn struct
    let asn_reader = GEOIP_ASN_READER.read().ok()?;
    if let Some((asn_reader, _)) = asn_reader.as_ref() {
        if let Ok(asn_lookup) = asn_reader.lookup(ip_addr) {
            if asn_lookup.has_data() {
                if let Ok(Some(asn_result)) = asn_lookup.decode::<maxminddb::geoip2::Asn>() {
                    geo_result.asn = asn_result.autonomous_system_number;
                    geo_result.asn_org = asn_result
                        .autonomous_system_organization
                        .map(|s| s.to_string());
                }
            }
        }
    }

    Some(geo_result)
}

/// Gets the current GeoIP City metadata if initialized
#[allow(dead_code)]
pub fn get_metadata() -> Option<GeoIpMetadata> {
    let reader = GEOIP_CITY_READER.read().ok()?;
    reader.as_ref().map(|(_, metadata)| metadata.clone())
}

/// Checks if GeoIP is enabled (database is loaded).
pub fn is_enabled() -> bool {
    GEOIP_CITY_READER
        .read()
        .ok()
        .and_then(|reader| reader.as_ref().map(|_| true))
        .unwrap_or(false)
}
