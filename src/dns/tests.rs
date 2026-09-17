//! Live-network DNS smoke tests (`#[ignore]`; `just test-e2e`).
//!
//! Hermetic contracts live next to the production helpers in `extract`,
//! `records`, and `resolution`.

use super::*;
use crate::initialization::test_resolver;

#[tokio::test]
#[ignore = "requires network DNS"]
async fn test_lookup_ns_records_success() {
    let resolver = test_resolver();
    let nameservers = lookup_ns_records("example.com", &resolver)
        .await
        .expect("example.com NS lookup should succeed with network");
    assert!(
        !nameservers.is_empty(),
        "example.com should have nameservers"
    );
    for ns in &nameservers {
        assert!(!ns.is_empty());
        assert!(ns.contains('.'));
    }
}

#[tokio::test]
#[ignore = "requires network DNS"]
async fn test_lookup_txt_records_success() {
    let resolver = test_resolver();
    lookup_txt_records("example.com", &resolver)
        .await
        .expect("example.com TXT lookup should succeed with network");
}

#[tokio::test]
#[ignore = "requires network DNS"]
async fn test_lookup_mx_records_success() {
    let resolver = test_resolver();
    let mx_records = lookup_mx_records("example.com", &resolver)
        .await
        .expect("example.com MX lookup should succeed with network");
    for (_priority, hostname) in &mx_records {
        assert!(!hostname.is_empty());
        assert!(hostname.contains('.'));
    }
    for i in 1..mx_records.len() {
        assert!(
            mx_records[i - 1].0 <= mx_records[i].0,
            "MX records should be sorted by priority"
        );
    }
}

#[tokio::test]
#[ignore = "requires network DNS"]
async fn test_dns_functions_with_valid_well_known_domains() {
    let resolver = test_resolver();
    let test_domains = ["example.com", "iana.org"];

    for domain in test_domains {
        let nameservers = lookup_ns_records(domain, &resolver)
            .await
            .unwrap_or_else(|e| panic!("NS lookup should succeed for {domain}: {e}"));
        assert!(!nameservers.is_empty(), "NS should exist for {domain}");

        lookup_txt_records(domain, &resolver)
            .await
            .unwrap_or_else(|e| panic!("TXT lookup should succeed for {domain}: {e}"));

        lookup_mx_records(domain, &resolver)
            .await
            .unwrap_or_else(|e| panic!("MX lookup should succeed for {domain}: {e}"));
    }
}
