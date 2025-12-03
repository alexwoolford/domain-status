//! DNS resolution and record querying.
//!
//! This module provides async DNS operations using `hickory-resolver`:
//! - IP address resolution (A/AAAA records)
//! - Nameserver queries (NS records)
//! - Text record queries (TXT records) with SPF/DMARC extraction
//! - Mail exchanger queries (MX records)
//!
//! All operations are async and respect system DNS configuration.

mod extract;
mod records;
mod resolution;

// Re-export public API
pub use extract::{extract_dmarc_record, extract_spf_record};
pub use records::{lookup_mx_records, lookup_ns_records, lookup_txt_records};
pub use resolution::{resolve_host_to_ip, reverse_dns_lookup};

#[cfg(test)]
mod tests;
