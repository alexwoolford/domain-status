//! DNS resolution and record querying.
//!
//! This module provides async DNS operations using `hickory-resolver`:
//! - IP address resolution (A/AAAA records)
//! - Nameserver queries (NS records)
//! - Text record queries (TXT records) with SPF/DMARC extraction
//! - Mail exchanger queries (MX records)
//!
//! All operations are async and respect system DNS configuration.
//!
//! ## Testing
//!
//! DNS tests use live resolution. For hermetic tests, consider a mock DNS server
//! (e.g. hickory-dns test-support style).

mod extract;
mod records;
mod resolution;

// Re-export public API
pub use extract::{
    is_spf_txt, is_dmarc_txt, extract_spf_record, extract_dmarc_record, is_mta_sts_txt, is_tls_rpt_txt, is_bimi_txt, extract_mta_sts_record, extract_tls_rpt_record, extract_bimi_record,
};
pub use records::{
    lookup_aaaa_records, lookup_caa_records, lookup_cname_records, lookup_mx_records,
    lookup_ns_records, lookup_txt_records,
};
pub use resolution::{resolve_host_to_ip, reverse_dns_lookup};

#[cfg(test)]
mod tests;
