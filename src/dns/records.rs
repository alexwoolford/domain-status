//! DNS record queries (NS, TXT, MX, CNAME, AAAA, CAA).

use anyhow::{Error, Result};
use hickory_resolver::net::NetError;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;

/// Maps a lookup error: NXDOMAIN / empty `RRset` → `Ok([])`, timeout and other
/// failures → `Err` (logged).
fn map_lookup_error<T>(domain: &str, label: &str, err: NetError) -> Result<Vec<T>, Error> {
    if err.is_no_records_found() || err.is_nx_domain() {
        return Ok(Vec::new());
    }
    if matches!(err, NetError::Timeout) {
        log::warn!("{label} record lookup timed out for {domain}: {err}");
    } else {
        log::warn!("Failed to lookup {label} records for {domain}: {err}");
    }
    Err(err.into())
}

async fn lookup_mapped<T>(
    domain: &str,
    resolver: &TokioResolver,
    record_type: RecordType,
    label: &str,
    map: impl Fn(&RData) -> Option<T>,
) -> Result<Vec<T>, Error> {
    match resolver.lookup(domain, record_type).await {
        Ok(lookup) => Ok(lookup
            .answers()
            .iter()
            .filter_map(|record| map(&record.data))
            .collect()),
        Err(err) => map_lookup_error(domain, label, err),
    }
}

/// Queries NS (nameserver) records for a domain.
///
/// Returns nameserver hostnames, or an empty vector when the name has no NS
/// records (including NXDOMAIN).
pub async fn lookup_ns_records(
    domain: &str,
    resolver: &TokioResolver,
) -> Result<Vec<String>, Error> {
    lookup_mapped(domain, resolver, RecordType::NS, "NS", |data| {
        if let RData::NS(ns) = data {
            Some(ns.to_utf8())
        } else {
            None
        }
    })
    .await
}

/// True when a TXT RDATA string is worth classifying and storing.
pub(crate) fn is_storable_txt(txt: &str) -> bool {
    !txt.trim().is_empty()
}

/// Truncates concatenated TXT RDATA to [`crate::config::MAX_TXT_RECORD_SIZE`]
/// **bytes** on a UTF-8 character boundary.
fn bound_txt_record(domain: &str, concatenated: String) -> String {
    let max = crate::config::MAX_TXT_RECORD_SIZE;
    if concatenated.len() <= max {
        return concatenated;
    }
    log::warn!(
        "TXT record for {domain} is {} bytes (limit: {max}), truncating (potential DNS tunneling attack)",
        concatenated.len()
    );
    crate::utils::sanitize::truncate_utf8(&concatenated, max)
}

fn take_storable_txt(records: impl IntoIterator<Item = String>) -> Vec<String> {
    records
        .into_iter()
        .filter(|txt| is_storable_txt(txt))
        .take(crate::config::MAX_TXT_RECORD_COUNT)
        .collect()
}

/// Queries TXT (text) records for a domain.
///
/// Empty/whitespace TXT strings are dropped. At most
/// [`crate::config::MAX_TXT_RECORD_COUNT`] records are returned; each is
/// truncated to [`crate::config::MAX_TXT_RECORD_SIZE`] bytes.
pub async fn lookup_txt_records(
    domain: &str,
    resolver: &TokioResolver,
) -> Result<Vec<String>, Error> {
    match resolver.lookup(domain, RecordType::TXT).await {
        Ok(lookup) => {
            let total_count = lookup
                .answers()
                .iter()
                .filter(|record| matches!(&record.data, RData::TXT(_)))
                .count();
            if total_count > crate::config::MAX_TXT_RECORD_COUNT {
                log::warn!(
                    "Domain {domain} has {total_count} TXT records (limit: {}), capping (potential DNS abuse)",
                    crate::config::MAX_TXT_RECORD_COUNT
                );
            }

            let records = lookup.answers().iter().filter_map(|record| {
                let RData::TXT(txt) = &record.data else {
                    return None;
                };
                let concatenated: String = txt
                    .txt_data
                    .iter()
                    .map(|bytes| String::from_utf8_lossy(bytes))
                    .collect();
                Some(bound_txt_record(domain, concatenated))
            });
            Ok(take_storable_txt(records))
        }
        Err(err) => map_lookup_error(domain, "TXT", err),
    }
}

/// Queries MX (mail exchanger) records for a domain.
///
/// Returns `(priority, hostname)` tuples sorted by priority (lower = higher
/// priority), or an empty vector when none exist.
pub async fn lookup_mx_records(
    domain: &str,
    resolver: &TokioResolver,
) -> Result<Vec<(u16, String)>, Error> {
    let mut mx_records = lookup_mapped(domain, resolver, RecordType::MX, "MX", |data| {
        if let RData::MX(mx) = data {
            Some((mx.preference, mx.exchange.to_utf8()))
        } else {
            None
        }
    })
    .await?;
    mx_records.sort_by_key(|(priority, _)| *priority);
    Ok(mx_records)
}

/// Queries CNAME records for a domain.
///
/// Returns CNAME target hostnames. Most domains have 0 or 1 CNAME, but chains
/// are possible.
pub async fn lookup_cname_records(
    domain: &str,
    resolver: &TokioResolver,
) -> Result<Vec<String>, Error> {
    lookup_mapped(domain, resolver, RecordType::CNAME, "CNAME", |data| {
        if let RData::CNAME(name) = data {
            Some(name.to_utf8())
        } else {
            None
        }
    })
    .await
}

/// Queries AAAA (IPv6) records for a domain.
///
/// Returns IPv6 addresses as strings.
pub async fn lookup_aaaa_records(
    domain: &str,
    resolver: &TokioResolver,
) -> Result<Vec<String>, Error> {
    lookup_mapped(domain, resolver, RecordType::AAAA, "AAAA", |data| {
        if let RData::AAAA(addr) = data {
            Some(addr.0.to_string())
        } else {
            None
        }
    })
    .await
}

/// Queries CAA (Certificate Authority Authorization) records for a domain.
///
/// Returns `(flag, tag, value)` tuples where flag is `0` (non-critical) or
/// `128` (issuer-critical).
pub async fn lookup_caa_records(
    domain: &str,
    resolver: &TokioResolver,
) -> Result<Vec<(u8, String, String)>, Error> {
    lookup_mapped(domain, resolver, RecordType::CAA, "CAA", |data| {
        if let RData::CAA(caa) = data {
            let flag = if caa.issuer_critical { 128u8 } else { 0u8 };
            Some((
                flag,
                caa.tag.clone(),
                String::from_utf8_lossy(&caa.value).into_owned(),
            ))
        } else {
            None
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{MAX_TXT_RECORD_COUNT, MAX_TXT_RECORD_SIZE};
    use hickory_resolver::net::NoRecords;
    use hickory_resolver::proto::op::{Query, ResponseCode};
    use hickory_resolver::proto::rr::{Name, RecordType};

    fn nxdomain() -> NetError {
        let name = Name::from_ascii("missing.example.").expect("label");
        NetError::from(NoRecords::new(
            Query::query(name, RecordType::NS),
            ResponseCode::NXDomain,
        ))
    }

    fn noerror_empty() -> NetError {
        let name = Name::from_ascii("empty.example.").expect("label");
        NetError::from(NoRecords::new(
            Query::query(name, RecordType::TXT),
            ResponseCode::NoError,
        ))
    }

    #[test]
    fn map_lookup_error_nxdomain_and_empty_are_ok_empty() {
        let nx: Result<Vec<String>, _> = map_lookup_error("missing.example", "NS", nxdomain());
        assert_eq!(nx.expect("NXDOMAIN"), Vec::<String>::new());
        let empty: Result<Vec<String>, _> =
            map_lookup_error("empty.example", "TXT", noerror_empty());
        assert_eq!(empty.expect("NOERROR empty"), Vec::<String>::new());
    }

    #[test]
    fn map_lookup_error_timeout_is_err() {
        let result: Result<Vec<String>, _> =
            map_lookup_error("slow.example", "NS", NetError::Timeout);
        assert!(result.is_err(), "timeout must not become an empty Ok");
    }

    #[test]
    fn is_storable_txt_rejects_empty_and_whitespace() {
        assert!(!is_storable_txt(""));
        assert!(!is_storable_txt(" \t\n"));
        assert!(is_storable_txt("v=spf1 ~all"));
    }

    #[test]
    fn bound_txt_record_caps_ascii_at_byte_limit() {
        let input = "a".repeat(MAX_TXT_RECORD_SIZE + 200);
        let bounded = bound_txt_record("example.com", input);
        assert_eq!(bounded.len(), MAX_TXT_RECORD_SIZE);
        assert_eq!(bounded.chars().count(), MAX_TXT_RECORD_SIZE);
    }

    #[test]
    fn bound_txt_record_utf8_stays_under_byte_cap_and_valid() {
        // 4-byte emoji so char-count truncation would exceed the byte budget.
        let unit = "🚀";
        assert_eq!(unit.len(), 4);
        let mut input = String::new();
        while input.len() <= MAX_TXT_RECORD_SIZE + unit.len() {
            input.push_str(unit);
        }
        let bounded = bound_txt_record("example.com", input);
        assert!(
            bounded.len() <= MAX_TXT_RECORD_SIZE,
            "bounded {} bytes exceeds cap {MAX_TXT_RECORD_SIZE}",
            bounded.len()
        );
        assert!(bounded.is_char_boundary(bounded.len()));
        assert!(std::str::from_utf8(bounded.as_bytes()).is_ok());
        assert!(
            bounded.chars().count() < MAX_TXT_RECORD_SIZE,
            "UTF-8 cap must be bytes, not chars"
        );
    }

    #[test]
    fn take_storable_txt_drops_empty_and_caps_count() {
        let mut records: Vec<String> = (0..=MAX_TXT_RECORD_COUNT)
            .map(|i| format!("txt-{i}"))
            .collect();
        records.insert(0, "   ".to_string());
        assert_eq!(records.len(), MAX_TXT_RECORD_COUNT + 2);
        let kept = take_storable_txt(records);
        assert_eq!(kept.len(), MAX_TXT_RECORD_COUNT);
        assert_eq!(kept[0], "txt-0");
        assert_eq!(
            kept[MAX_TXT_RECORD_COUNT - 1],
            format!("txt-{}", MAX_TXT_RECORD_COUNT - 1)
        );
    }
}
