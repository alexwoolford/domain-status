//! IP address resolution and reverse DNS lookup.
//!
//! This module provides functions to resolve hostnames to IP addresses
//! and perform reverse DNS lookups (PTR records).

use anyhow::{Error, Result};
use hickory_resolver::TokioAsyncResolver;

/// Resolves a hostname to an IP address using DNS.
///
/// # Arguments
///
/// * `host` - The hostname to resolve
/// * `resolver` - The DNS resolver instance
///
/// # Returns
///
/// The first IP address found, or an error if resolution fails.
///
/// # Errors
///
/// Returns an error if DNS resolution fails or no IP addresses are found.
pub async fn resolve_host_to_ip(
    host: &str,
    resolver: &TokioAsyncResolver,
) -> Result<String, Error> {
    // In 0.24, this worked fine without FQDN workarounds
    let response = resolver.lookup_ip(host).await.map_err(Error::new)?;
    let ip = response
        .iter()
        .next()
        .ok_or_else(|| Error::msg("No IP addresses found"))?
        .to_string();
    Ok(ip)
}

/// Performs a reverse DNS lookup (PTR record) for an IP address.
///
/// # Arguments
///
/// * `ip` - The IP address to look up
/// * `resolver` - The DNS resolver instance
///
/// # Returns
///
/// The reverse DNS name, or `None` if the lookup fails.
pub async fn reverse_dns_lookup(
    ip: &str,
    resolver: &TokioAsyncResolver,
) -> Result<Option<String>, Error> {
    match resolver.reverse_lookup(ip.parse()?).await {
        Ok(response) => {
            let name = response.iter().next().map(|name| name.to_utf8());
            Ok(name)
        }
        Err(e) => {
            log::warn!("Failed to perform reverse DNS lookup for {ip}: {e}");
            Ok(None)
        }
    }
}
