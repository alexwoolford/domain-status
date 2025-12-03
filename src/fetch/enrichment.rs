//! Data enrichment lookups.
//!
//! This module handles enrichment lookups including GeoIP, WHOIS, and security analysis.

use std::collections::HashMap;

/// Performs enrichment lookups (GeoIP, WHOIS, security analysis).
///
/// # Arguments
///
/// * `ip_address` - The IP address for GeoIP lookup
/// * `final_url` - The final URL for security analysis
/// * `final_domain` - The final domain for WHOIS lookup
/// * `tls_version` - TLS version for security analysis
/// * `security_headers` - Security headers for analysis
/// * `enable_whois` - Whether to perform WHOIS lookup
///
/// # Returns
///
/// A tuple of (geoip_data, security_warnings, whois_data).
#[allow(dead_code)] // Kept for potential future use or reference
pub(crate) async fn perform_enrichment_lookups(
    ip_address: &str,
    final_url: &str,
    final_domain: &str,
    tls_version: &Option<String>,
    security_headers: &HashMap<String, String>,
    enable_whois: bool,
) -> (
    Option<(String, crate::geoip::GeoIpResult)>,
    Vec<crate::security::SecurityWarning>,
    Option<crate::whois::WhoisResult>,
) {
    let geoip_data =
        crate::geoip::lookup_ip(ip_address).map(|result| (ip_address.to_string(), result));

    let security_warnings =
        crate::security::analyze_security(final_url, tls_version, security_headers);

    let whois_data = if enable_whois {
        log::info!("Performing WHOIS lookup for domain: {}", final_domain);
        match crate::whois::lookup_whois(final_domain, None).await {
            Ok(Some(whois_result)) => {
                log::info!(
                    "WHOIS lookup successful for {}: registrar={:?}, creation={:?}, expiration={:?}",
                    final_domain,
                    whois_result.registrar,
                    whois_result.creation_date,
                    whois_result.expiration_date
                );
                Some(whois_result)
            }
            Ok(None) => {
                log::info!("WHOIS lookup returned no data for {}", final_domain);
                None
            }
            Err(e) => {
                log::warn!("WHOIS lookup failed for {}: {}", final_domain, e);
                None
            }
        }
    } else {
        None
    };

    (geoip_data, security_warnings, whois_data)
}
