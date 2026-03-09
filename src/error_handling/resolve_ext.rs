//! Predicate-based categorization for `hickory_resolver::ResolveError`.
//!
//! Provides a stable way to map resolver errors to domain_status-friendly kinds
//! without string matching, so DNS categorization is consistent across
//! `dns/records.rs` and `extract_error_type()`.

use hickory_resolver::proto::ProtoErrorKind;
use hickory_resolver::ResolveError;

/// Kind of DNS resolution error for categorization (predicate-based, not string-based).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsResolveErrorKind {
    /// Domain does not exist (NXDOMAIN).
    NxDomain,
    /// No records found for the query (empty answer).
    NoRecords,
    /// Resolution timed out.
    Timeout,
    /// Other resolution error (network, server, etc.).
    Other,
}

/// Categorizes a resolver error using its predicate API.
///
/// Use this when you have a `ResolveError` (e.g. from the error chain) so DNS
/// categorization does not rely on error message text.
pub fn categorize_resolve_error(e: &ResolveError) -> DnsResolveErrorKind {
    if e.is_nx_domain() {
        return DnsResolveErrorKind::NxDomain;
    }
    if e.is_no_records_found() {
        return DnsResolveErrorKind::NoRecords;
    }
    let is_timeout = e
        .proto()
        .is_some_and(|p| matches!(p.kind(), ProtoErrorKind::Timeout));
    if is_timeout {
        return DnsResolveErrorKind::Timeout;
    }
    DnsResolveErrorKind::Other
}
