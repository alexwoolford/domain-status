use anyhow::{Error, Result};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;

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
pub async fn resolve_host_to_ip(host: &str, resolver: &TokioResolver) -> Result<String, Error> {
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
    resolver: &TokioResolver,
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

/// Queries NS (nameserver) records for a domain.
///
/// # Arguments
///
/// * `domain` - The domain to query
/// * `resolver` - The DNS resolver instance
///
/// # Returns
///
/// A vector of nameserver hostnames, or an empty vector if the query fails.
pub async fn lookup_ns_records(
    domain: &str,
    resolver: &TokioResolver,
) -> Result<Vec<String>, Error> {
    match resolver.lookup(domain, RecordType::NS).await {
        Ok(lookup) => {
            let nameservers: Vec<String> = lookup
                .iter()
                .filter_map(|rdata| {
                    if let RData::NS(ns) = rdata {
                        Some(ns.to_utf8())
                    } else {
                        None
                    }
                })
                .collect();
            Ok(nameservers)
        }
        Err(e) => {
            log::warn!("Failed to lookup NS records for {domain}: {e}");
            Ok(Vec::new())
        }
    }
}

/// Queries TXT records for a domain.
///
/// TXT records commonly contain SPF, DMARC, DKIM, and other policy records.
///
/// # Arguments
///
/// * `domain` - The domain to query
/// * `resolver` - The DNS resolver instance
///
/// # Returns
///
/// A vector of TXT record strings, or an empty vector if the query fails.
pub async fn lookup_txt_records(
    domain: &str,
    resolver: &TokioResolver,
) -> Result<Vec<String>, Error> {
    match resolver.lookup(domain, RecordType::TXT).await {
        Ok(lookup) => {
            let txt_records: Vec<String> = lookup
                .iter()
                .filter_map(|rdata| {
                    if let RData::TXT(txt) = rdata {
                        // TXT records can be split across multiple byte slices, join them
                        // Convert each byte slice to a string, handling UTF-8
                        let parts: Result<Vec<String>, _> = txt
                            .iter()
                            .map(|bytes| String::from_utf8(bytes.to_vec()))
                            .collect();
                        parts.ok().map(|parts| parts.join(""))
                    } else {
                        None
                    }
                })
                .collect();
            Ok(txt_records)
        }
        Err(e) => {
            log::warn!("Failed to lookup TXT records for {domain}: {e}");
            Ok(Vec::new())
        }
    }
}

/// Queries MX (mail exchange) records for a domain.
///
/// # Arguments
///
/// * `domain` - The domain to query
/// * `resolver` - The DNS resolver instance
///
/// # Returns
///
/// A vector of tuples (priority, hostname), sorted by priority (lower is higher priority),
/// or an empty vector if the query fails.
pub async fn lookup_mx_records(
    domain: &str,
    resolver: &TokioResolver,
) -> Result<Vec<(u16, String)>, Error> {
    match resolver.lookup(domain, RecordType::MX).await {
        Ok(lookup) => {
            let mut mx_records: Vec<(u16, String)> = lookup
                .iter()
                .filter_map(|rdata| {
                    if let RData::MX(mx) = rdata {
                        Some((mx.preference(), mx.exchange().to_utf8()))
                    } else {
                        None
                    }
                })
                .collect();
            // Sort by priority (lower preference = higher priority)
            mx_records.sort_by_key(|(priority, _)| *priority);
            Ok(mx_records)
        }
        Err(e) => {
            log::warn!("Failed to lookup MX records for {domain}: {e}");
            Ok(Vec::new())
        }
    }
}

/// Extracts SPF record from TXT records.
///
/// SPF records start with "v=spf1".
///
/// # Arguments
///
/// * `txt_records` - Vector of TXT record strings
///
/// # Returns
///
/// The first SPF record found, or `None` if no SPF record exists.
pub fn extract_spf_record(txt_records: &[String]) -> Option<String> {
    txt_records
        .iter()
        .find(|txt| txt.trim().starts_with("v=spf1"))
        .map(|s| s.trim().to_string())
}

/// Extracts DMARC record from TXT records.
///
/// DMARC records are typically at `_dmarc.<domain>` but we check the provided records.
/// DMARC records start with "v=DMARC1".
///
/// # Arguments
///
/// * `txt_records` - Vector of TXT record strings
///
/// # Returns
///
/// The first DMARC record found, or `None` if no DMARC record exists.
pub fn extract_dmarc_record(txt_records: &[String]) -> Option<String> {
    txt_records
        .iter()
        .find(|txt| txt.trim().starts_with("v=DMARC1"))
        .map(|s| s.trim().to_string())
}
