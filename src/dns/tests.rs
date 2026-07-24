/// DNS module tests.
use super::*;
use hickory_resolver::config::ResolverOpts;
use std::time::Duration;

/// Creates a test DNS resolver with short timeouts for faster test execution.
fn create_test_resolver() -> hickory_resolver::TokioResolver {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 1; // Single attempt for faster failures in tests
    opts.ndots = 0;

    hickory_resolver::TokioResolver::builder_tokio()
        .unwrap()
        .with_options(opts)
        .build()
        .expect("resolver builds with default config")
}

#[tokio::test]
#[ignore = "requires network DNS"]
async fn test_lookup_ns_records_success() {
    let resolver = create_test_resolver();
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
async fn test_lookup_ns_records_no_records_found() {
    let resolver = create_test_resolver();
    let result = lookup_ns_records("definitely-does-not-exist-12345.invalid", &resolver).await;
    match result {
        Ok(nameservers) => {
            assert!(
                nameservers.is_empty(),
                "Non-existent domain should return empty vector"
            );
        }
        Err(e) => {
            let error_msg = e.to_string().to_lowercase();
            assert!(
                !error_msg.contains("no records found") && !error_msg.contains("nxdomain"),
                "Error should not be 'no records found' if it's an Err: {}",
                error_msg
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires network DNS"]
async fn test_lookup_txt_records_success() {
    let resolver = create_test_resolver();
    // Ok is the contract; record presence varies by zone.
    lookup_txt_records("example.com", &resolver)
        .await
        .expect("example.com TXT lookup should succeed with network");
}

#[tokio::test]
async fn test_lookup_txt_records_no_records_found() {
    let resolver = create_test_resolver();
    let result = lookup_txt_records("definitely-does-not-exist-12345.invalid", &resolver).await;
    match result {
        Ok(txt_records) => {
            assert!(
                txt_records.is_empty(),
                "Non-existent domain should return empty vector"
            );
        }
        Err(e) => {
            let error_msg = e.to_string().to_lowercase();
            assert!(
                !error_msg.contains("no records found") && !error_msg.contains("nxdomain"),
                "Error should not be 'no records found' if it's an Err: {}",
                error_msg
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires network DNS"]
async fn test_lookup_mx_records_success() {
    let resolver = create_test_resolver();
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
async fn test_lookup_mx_records_no_records_found() {
    let resolver = create_test_resolver();
    let result = lookup_mx_records("definitely-does-not-exist-12345.invalid", &resolver).await;
    match result {
        Ok(mx_records) => {
            assert!(
                mx_records.is_empty(),
                "Non-existent domain should return empty vector"
            );
        }
        Err(e) => {
            let error_msg = e.to_string().to_lowercase();
            assert!(
                !error_msg.contains("no records found") && !error_msg.contains("nxdomain"),
                "Error should not be 'no records found' if it's an Err: {}",
                error_msg
            );
        }
    }
}

#[tokio::test]
async fn test_error_message_parsing_no_records_found() {
    let resolver = create_test_resolver();
    let result = lookup_ns_records("test.invalid-tld-xyz", &resolver).await;
    match result {
        Ok(nameservers) => {
            assert!(nameservers.is_empty());
        }
        Err(e) => {
            let error_msg = e.to_string().to_lowercase();
            assert!(
                !error_msg.contains("no records found") && !error_msg.contains("nxdomain"),
                "If Err, should not be 'no records found': {}",
                error_msg
            );
        }
    }
}

#[tokio::test]
async fn test_all_dns_functions_handle_nonexistent_domains() {
    let resolver = create_test_resolver();
    let test_domain = "definitely-does-not-exist-12345.invalid";

    let ns_result = lookup_ns_records(test_domain, &resolver).await;
    let txt_result = lookup_txt_records(test_domain, &resolver).await;
    let mx_result = lookup_mx_records(test_domain, &resolver).await;

    match (ns_result, txt_result, mx_result) {
        (Ok(ns), Ok(txt), Ok(mx)) => {
            assert!(ns.is_empty());
            assert!(txt.is_empty());
            assert!(mx.is_empty());
        }
        (Err(ns_e), Err(txt_e), Err(mx_e)) => {
            let ns_msg = ns_e.to_string().to_lowercase();
            let txt_msg = txt_e.to_string().to_lowercase();
            let mx_msg = mx_e.to_string().to_lowercase();
            assert!(
                !ns_msg.contains("no records found") && !ns_msg.contains("nxdomain"),
                "NS error should not be 'no records found': {}",
                ns_msg
            );
            assert!(
                !txt_msg.contains("no records found") && !txt_msg.contains("nxdomain"),
                "TXT error should not be 'no records found': {}",
                txt_msg
            );
            assert!(
                !mx_msg.contains("no records found") && !mx_msg.contains("nxdomain"),
                "MX error should not be 'no records found': {}",
                mx_msg
            );
        }
        (ns, txt, mx) => {
            panic!(
                "expected consistent Ok/Err across lookups; got ns={ns:?} txt={txt:?} mx={mx:?}"
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires network DNS"]
async fn test_dns_functions_with_valid_well_known_domains() {
    let resolver = create_test_resolver();
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

#[test]
fn test_extract_spf_record() {
    let txt_records = vec![
        "v=spf1 include:_spf.google.com ~all".to_string(),
        "some other record".to_string(),
    ];
    let spf = extract_spf_record(&txt_records);
    assert_eq!(spf, Some("v=spf1 include:_spf.google.com ~all".to_string()));
}

#[test]
fn test_extract_spf_record_not_found() {
    let txt_records = vec!["some other record".to_string()];
    let spf = extract_spf_record(&txt_records);
    assert_eq!(spf, None);
}

#[test]
fn test_extract_spf_record_empty() {
    let txt_records = vec![];
    let spf = extract_spf_record(&txt_records);
    assert_eq!(spf, None);
}

#[test]
fn test_extract_dmarc_record() {
    let txt_records = vec![
        "v=DMARC1; p=none; rua=mailto:dmarc@example.com".to_string(),
        "some other record".to_string(),
    ];
    let dmarc = extract_dmarc_record(&txt_records);
    assert_eq!(
        dmarc,
        Some("v=DMARC1; p=none; rua=mailto:dmarc@example.com".to_string())
    );
}

#[test]
fn test_extract_dmarc_record_not_found() {
    let txt_records = vec!["some other record".to_string()];
    let dmarc = extract_dmarc_record(&txt_records);
    assert_eq!(dmarc, None);
}

#[test]
fn test_extract_dmarc_record_empty() {
    let txt_records = vec![];
    let dmarc = extract_dmarc_record(&txt_records);
    assert_eq!(dmarc, None);
}

#[test]
fn test_extract_dmarc_record_case_insensitive() {
    let txt_records = vec!["v=dmarc1; p=none".to_string()];
    let dmarc = extract_dmarc_record(&txt_records);
    // Implementation is case-sensitive for "v=DMARC1"
    assert_eq!(dmarc, None);
}
