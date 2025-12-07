//! DNS record queries (NS, TXT, MX).
//!
//! This module provides functions to query various DNS record types:
//! - Nameserver records (NS)
//! - Text records (TXT)
//! - Mail exchanger records (MX)

use anyhow::{Error, Result};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;

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
    // For TXT/NS/MX lookups, use domain as-is (no trailing dot needed)
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
            let error_msg = e.to_string();
            // "no records found" is expected for some domains - return empty vector
            if error_msg.contains("no records found") || error_msg.contains("NXDomain") {
                Ok(Vec::new())
            } else {
                // Actual failures (timeouts, network errors, etc.) should be propagated as errors
                // so they can be recorded as partial failures
                if error_msg.contains("timeout") || error_msg.contains("timed out") {
                    log::warn!("NS record lookup timed out for {domain}: {e}");
                } else {
                    log::warn!("Failed to lookup NS records for {domain}: {e}");
                }
                Err(e.into())
            }
        }
    }
}

/// Queries TXT (text) records for a domain.
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
                        // TXT records can contain multiple strings - join them
                        Some(
                            txt.iter()
                                .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                                .collect::<Vec<String>>()
                                .join(""),
                        )
                    } else {
                        None
                    }
                })
                .collect();
            Ok(txt_records)
        }
        Err(e) => {
            let error_msg = e.to_string();
            // "no records found" is expected for domains without TXT records - return empty vector
            if error_msg.contains("no records found") || error_msg.contains("NXDomain") {
                Ok(Vec::new())
            } else {
                // Actual failures (timeouts, network errors, etc.) should be propagated as errors
                // so they can be recorded as partial failures
                if error_msg.contains("timeout") || error_msg.contains("timed out") {
                    log::warn!("TXT record lookup timed out for {domain}: {e}");
                } else {
                    log::warn!("Failed to lookup TXT records for {domain}: {e}");
                }
                Err(e.into())
            }
        }
    }
}

/// Queries MX (mail exchanger) records for a domain.
///
/// # Arguments
///
/// * `domain` - The domain to query
/// * `resolver` - The DNS resolver instance
///
/// # Returns
///
/// A vector of (priority, hostname) tuples, sorted by priority (lower = higher priority).
/// Returns an empty vector if the query fails or no MX records exist.
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
            let error_msg = e.to_string();
            // "no records found" is expected for domains without mail servers - return empty vector
            if error_msg.contains("no records found") || error_msg.contains("NXDomain") {
                Ok(Vec::new())
            } else {
                // Actual failures (timeouts, network errors, etc.) should be propagated as errors
                // so they can be recorded as partial failures
                if error_msg.contains("timeout") || error_msg.contains("timed out") {
                    log::warn!("MX record lookup timed out for {domain}: {e}");
                } else {
                    log::warn!("Failed to lookup MX records for {domain}: {e}");
                }
                Err(e.into())
            }
        }
    }
}
