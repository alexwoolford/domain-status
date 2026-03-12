//! DNS record queries (NS, TXT, MX).
//!
//! This module provides functions to query various DNS record types:
//! - Nameserver records (NS)
//! - Text records (TXT)
//! - Mail exchanger records (MX)

use anyhow::{Error, Result};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::proto::ProtoErrorKind;
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
            // Use resolver error predicates (stable API) instead of string matching.
            if e.is_no_records_found() || e.is_nx_domain() {
                Ok(Vec::new())
            } else {
                let is_timeout = e
                    .proto()
                    .is_some_and(|p| matches!(p.kind(), ProtoErrorKind::Timeout));
                if is_timeout {
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
            // Count total TXT records for logging
            let total_count = lookup.iter().filter(|r| matches!(r, RData::TXT(_))).count();
            if total_count > crate::config::MAX_TXT_RECORD_COUNT {
                log::warn!(
                    "Domain {} has {} TXT records (limit: {}), capping (potential DNS abuse)",
                    domain,
                    total_count,
                    crate::config::MAX_TXT_RECORD_COUNT
                );
            }

            let txt_records: Vec<String> = lookup
                .iter()
                // Cap the number of TXT records to prevent memory/storage exhaustion
                .take(crate::config::MAX_TXT_RECORD_COUNT)
                .filter_map(|rdata| {
                    if let RData::TXT(txt) = rdata {
                        // TXT records can contain multiple strings - join them
                        let concatenated: String = txt
                            .iter()
                            .map(|bytes| String::from_utf8_lossy(bytes).to_string())
                            .collect::<Vec<String>>()
                            .join("");

                        // Truncate to MAX_TXT_RECORD_SIZE to prevent memory exhaustion from DNS tunneling
                        let original_len = concatenated.len();
                        let truncated = if original_len > crate::config::MAX_TXT_RECORD_SIZE {
                            log::warn!(
                                "TXT record for {} is {} bytes (limit: {}), truncating (potential DNS tunneling attack)",
                                domain,
                                original_len,
                                crate::config::MAX_TXT_RECORD_SIZE
                            );
                            // Truncate by character count (not byte index) to avoid
                            // panicking on multi-byte UTF-8 boundaries
                            concatenated
                                .chars()
                                .take(crate::config::MAX_TXT_RECORD_SIZE)
                                .collect::<String>()
                        } else {
                            concatenated
                        };

                        Some(truncated)
                    } else {
                        None
                    }
                })
                .collect();
            Ok(txt_records)
        }
        Err(e) => {
            if e.is_no_records_found() || e.is_nx_domain() {
                Ok(Vec::new())
            } else {
                let is_timeout = e
                    .proto()
                    .is_some_and(|p| matches!(p.kind(), ProtoErrorKind::Timeout));
                if is_timeout {
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
            if e.is_no_records_found() || e.is_nx_domain() {
                Ok(Vec::new())
            } else {
                let is_timeout = e
                    .proto()
                    .is_some_and(|p| matches!(p.kind(), ProtoErrorKind::Timeout));
                if is_timeout {
                    log::warn!("MX record lookup timed out for {domain}: {e}");
                } else {
                    log::warn!("Failed to lookup MX records for {domain}: {e}");
                }
                Err(e.into())
            }
        }
    }
}

/// Queries CNAME records for a domain.
///
/// Returns the CNAME target hostnames. Most domains have 0 or 1 CNAME,
/// but chains are possible (A -> B -> C).
pub async fn lookup_cname_records(
    domain: &str,
    resolver: &TokioResolver,
) -> Result<Vec<String>, Error> {
    match resolver.lookup(domain, RecordType::CNAME).await {
        Ok(lookup) => {
            let cnames: Vec<String> = lookup
                .iter()
                .filter_map(|rdata| {
                    if let RData::CNAME(name) = rdata {
                        Some(name.to_utf8())
                    } else {
                        None
                    }
                })
                .collect();
            Ok(cnames)
        }
        Err(e) => {
            if e.is_no_records_found() || e.is_nx_domain() {
                Ok(Vec::new())
            } else {
                let is_timeout = e
                    .proto()
                    .is_some_and(|p| matches!(p.kind(), ProtoErrorKind::Timeout));
                if is_timeout {
                    log::warn!("CNAME record lookup timed out for {domain}: {e}");
                } else {
                    log::warn!("Failed to lookup CNAME records for {domain}: {e}");
                }
                Err(e.into())
            }
        }
    }
}

/// Queries AAAA (IPv6) records for a domain.
///
/// Returns IPv6 addresses as strings.
pub async fn lookup_aaaa_records(
    domain: &str,
    resolver: &TokioResolver,
) -> Result<Vec<String>, Error> {
    match resolver.lookup(domain, RecordType::AAAA).await {
        Ok(lookup) => {
            let addresses: Vec<String> = lookup
                .iter()
                .filter_map(|rdata| {
                    if let RData::AAAA(addr) = rdata {
                        Some(addr.0.to_string())
                    } else {
                        None
                    }
                })
                .collect();
            Ok(addresses)
        }
        Err(e) => {
            if e.is_no_records_found() || e.is_nx_domain() {
                Ok(Vec::new())
            } else {
                let is_timeout = e
                    .proto()
                    .is_some_and(|p| matches!(p.kind(), ProtoErrorKind::Timeout));
                if is_timeout {
                    log::warn!("AAAA record lookup timed out for {domain}: {e}");
                } else {
                    log::warn!("Failed to lookup AAAA records for {domain}: {e}");
                }
                Err(e.into())
            }
        }
    }
}

/// Queries CAA (Certificate Authority Authorization) records for a domain.
///
/// Returns a vector of (flag, tag, value) tuples where:
/// - flag: 0 = non-critical, 128 = issuer-critical
/// - tag: "issue", "issuewild", or "iodef"
/// - value: CA domain or reporting URI
pub async fn lookup_caa_records(
    domain: &str,
    resolver: &TokioResolver,
) -> Result<Vec<(u8, String, String)>, Error> {
    match resolver.lookup(domain, RecordType::CAA).await {
        Ok(lookup) => {
            let records: Vec<(u8, String, String)> = lookup
                .iter()
                .filter_map(|rdata| {
                    if let RData::CAA(caa) = rdata {
                        let flag = if caa.issuer_critical() { 128u8 } else { 0u8 };
                        let tag = caa.tag().as_str().to_string();
                        let value = String::from_utf8_lossy(caa.raw_value()).to_string();
                        Some((flag, tag, value))
                    } else {
                        None
                    }
                })
                .collect();
            Ok(records)
        }
        Err(e) => {
            if e.is_no_records_found() || e.is_nx_domain() {
                Ok(Vec::new())
            } else {
                let is_timeout = e
                    .proto()
                    .is_some_and(|p| matches!(p.kind(), ProtoErrorKind::Timeout));
                if is_timeout {
                    log::warn!("CAA record lookup timed out for {domain}: {e}");
                } else {
                    log::warn!("Failed to lookup CAA records for {domain}: {e}");
                }
                Err(e.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{MAX_TXT_RECORD_COUNT, MAX_TXT_RECORD_SIZE};

    /// Documents intent: TXT limits must be in a reasonable range to prevent memory exhaustion
    /// in `lookup_txt_records`. Count 1-100, size 512-4096 bytes, worst case under 100KB.
    #[test]
    fn test_txt_record_limits_reasonable() {
        assert!(
            (1..=100).contains(&MAX_TXT_RECORD_COUNT),
            "TXT record count limit should be 1-100"
        );
        assert!(
            (512..=4096).contains(&MAX_TXT_RECORD_SIZE),
            "TXT record size limit should be 512-4096 bytes"
        );
        let worst_case_bytes = MAX_TXT_RECORD_COUNT * MAX_TXT_RECORD_SIZE;
        assert!(
            worst_case_bytes <= 100 * 1024,
            "Worst case TXT bytes per domain should be under 100KB"
        );
    }
}
