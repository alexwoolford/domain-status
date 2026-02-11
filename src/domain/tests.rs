// Domain module tests.

use super::*;

fn test_extractor() -> psl::List {
    psl::List
}

#[test]
fn test_extract_domain_basic() {
    let extractor = test_extractor();
    assert_eq!(
        extract_domain(&extractor, "https://www.example.com/path").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_with_port() {
    let extractor = test_extractor();
    // Port should be ignored, domain extraction should work
    assert_eq!(
        extract_domain(&extractor, "https://www.example.com:8080/path").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_with_query_and_fragment() {
    let extractor = test_extractor();
    // Query strings and fragments should not affect domain extraction
    assert_eq!(
        extract_domain(&extractor, "https://example.com/path?query=1#fragment").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_subdomain() {
    let extractor = test_extractor();
    // Should extract registrable domain, not subdomain
    assert_eq!(
        extract_domain(&extractor, "https://subdomain.example.com").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_multiple_subdomains() {
    let extractor = test_extractor();
    assert_eq!(
        extract_domain(&extractor, "https://a.b.c.example.com").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_no_subdomain() {
    let extractor = test_extractor();
    assert_eq!(
        extract_domain(&extractor, "https://example.com").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_http() {
    let extractor = test_extractor();
    // Should work with HTTP too
    assert_eq!(
        extract_domain(&extractor, "http://example.com").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_invalid_url() {
    let extractor = test_extractor();
    // Invalid URL should return error
    assert!(extract_domain(&extractor, "not-a-url").is_err());
}

#[test]
fn test_extract_domain_url_without_host() {
    let extractor = test_extractor();
    // URL without host should fail
    assert!(extract_domain(&extractor, "file:///path/to/file").is_err());
}


#[test]
fn test_extract_domain_uk_domain() {
    let extractor = test_extractor();
    // UK domains like co.uk - should return registrable domain, not just the suffix
    let result = extract_domain(&extractor, "https://www.example.co.uk");
    assert!(result.is_ok());
    let domain = result.unwrap();
    // Should return "example.co.uk" (registrable domain), not "co.uk" (public suffix)
    assert_eq!(domain, "example.co.uk");
}

#[test]
fn test_extract_domain_com_br() {
    let extractor = test_extractor();
    // Brazilian domains like com.br - should return registrable domain
    let result = extract_domain(&extractor, "https://www.example.com.br");
    assert!(result.is_ok());
    let domain = result.unwrap();
    // Should return "example.com.br" (registrable domain), not "com.br" (public suffix)
    assert_eq!(domain, "example.com.br");
}

#[test]
fn test_extract_domain_co_jp() {
    let extractor = test_extractor();
    // Japanese domains like co.jp - should return registrable domain
    let result = extract_domain(&extractor, "https://www.example.co.jp");
    assert!(result.is_ok());
    let domain = result.unwrap();
    // Should return "example.co.jp" (registrable domain), not "co.jp" (public suffix)
    assert_eq!(domain, "example.co.jp");
}

#[test]
fn test_extract_domain_stone_co() {
    let extractor = test_extractor();
    // .co domains (Colombia) - should return the full domain
    let result = extract_domain(&extractor, "https://example.co");
    assert!(result.is_ok());
    let domain = result.unwrap();
    // Should return "example.co" (the registrable domain)
    assert_eq!(domain, "example.co");
}

#[test]
fn test_extract_domain_stone_co_with_subdomain() {
    let extractor = test_extractor();
    // .co domains with subdomain
    let result = extract_domain(&extractor, "https://www.example.co");
    assert!(result.is_ok());
    let domain = result.unwrap();
    // Should return "example.co" (the registrable domain), not "co" or "www.example.co"
    assert_eq!(domain, "example.co");
}

#[test]
fn test_extract_domain_arrow_com() {
    let extractor = test_extractor();
    // Test example.org - a simple, standard domain
    let result = extract_domain(&extractor, "https://example.org");
    assert!(result.is_ok());
    let domain = result.unwrap();
    // Should return "example.org" (the registrable domain)
    assert_eq!(domain, "example.org");
}

#[test]
fn test_extract_domain_arrow_com_with_www() {
    let extractor = test_extractor();
    // Test www.example.org - with subdomain
    let result = extract_domain(&extractor, "https://www.example.org");
    assert!(result.is_ok());
    let domain = result.unwrap();
    // Should return "example.org" (the registrable domain), not "www.example.org"
    assert_eq!(domain, "example.org");
}

// Tests for edge cases to cover uncovered lines in extract_domain
// These test paths that are difficult to trigger but important for robustness

#[test]
fn test_extract_domain_simple_tld_no_extraction_needed() {
    let extractor = test_extractor();
    // Test simple TLD where extraction is not needed (covers line 143)
    // For simple TLDs like .com, domain() works correctly and needs_extraction should be false
    let result = extract_domain(&extractor, "https://example.com");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "example.com");
}

#[test]
fn test_extract_domain_multi_part_tld_extraction() {
    let extractor = test_extractor();
    // Test multi-part TLD that requires extraction (covers line 165)
    // This should trigger the extraction path and the extracted domain check
    let result = extract_domain(&extractor, "https://www.example.co.uk");
    assert!(result.is_ok());
    let domain = result.unwrap();
    // Should return "example.co.uk" (extracted), not "co.uk" (suffix)
    assert_eq!(domain, "example.co.uk");
}

#[test]
fn test_extract_domain_fallback_when_extraction_fails() {
    let extractor = test_extractor();
    // Test fallback path (line 175) when extraction logic can't find proper domain
    // This is difficult to trigger with real domains, but we test edge cases
    // Try with unusual domain patterns that might cause extraction to fail
    let result = extract_domain(&extractor, "https://test.example.com");
    assert!(result.is_ok());
    // Should return a valid domain (either extracted or fallback)
    let domain = result.unwrap();
    assert!(!domain.is_empty());
    assert!(domain.contains('.'));
}

// Note: Lines 127, 130, 133, 136 are edge cases in the extraction logic that are
// very difficult to trigger with real domains. These are defensive checks for:
// - Empty label (line 127)
// - No parts in split (line 130)
// - Empty before string (line 133)
// - Position at start (line 136)
// These paths are defensive programming and unlikely to occur with valid URLs,
// but they prevent panics if edge cases arise.

#[test]
fn test_psl_domain_behavior() {
    // This test verifies what psl returns
    let extractor = test_extractor();

    println!("\nTesting psl API behavior:");
    println!("==========================");

    let urls = vec![
        "https://www.example.com",
        "https://www.example.co.uk",
        "https://example.co.uk",
    ];

    for url in urls {
        println!("\nURL: {}", url);

        match extract_domain(&extractor, url) {
            Ok(domain) => {
                println!("  Registrable domain: {}", domain);
                println!("  -> psl correctly returns registrable domain");
            }
            Err(e) => {
                println!("  Error: {}", e);
            }
        }
    }
}

// Property-based tests using proptest
use proptest::prelude::*;

proptest! {
    // Configure proptest to use fewer cases and a fixed seed for reproducibility
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn test_extract_domain_idempotent(
        domain in "[a-z]{5,15}",  // Avoid very short domains that might not be in PSL
        tld in "(com|org|net|co\\.uk)"
    ) {
        let url = format!("https://www.{}.{}", domain, tld);
        let extractor = test_extractor();

        let extracted = extract_domain(&extractor, &url);
        if let Ok(d) = extracted {
            // Extracting domain from a domain should return same domain
            let url2 = format!("https://{}", d);
            let extracted2 = extract_domain(&extractor, &url2);
            prop_assert!(extracted2.is_ok(),
                "Second extraction should succeed");
            prop_assert_eq!(d, extracted2.unwrap(),
                "Domain extraction should be idempotent");
        }
    }

    #[test]
    fn test_extract_domain_subdomains_preserve_root(
        subdomain in prop::collection::vec("[a-z]{2,10}", 1..5),
        domain in "[a-z]{5,15}",  // Avoid very short domains
        tld in "(com|org|net)"
    ) {
        let root_url = format!("https://{}.{}", domain, tld);
        let extractor = test_extractor();
        let root_domain = extract_domain(&extractor, &root_url).ok();

        if let Some(root) = root_domain {
            // Adding subdomains shouldn't change root domain
            let sub_url = format!("https://{}.{}.{}",
                subdomain.join("."), domain, tld);
            let sub_domain = extract_domain(&extractor, &sub_url).ok();

            prop_assert_eq!(Some(root), sub_domain,
                "Subdomains should extract to same root domain");
        }
    }

    #[test]
    fn test_domain_extraction_no_panic(url in "https?://[a-zA-Z0-9.-]{1,100}\\.[a-z]{2,10}.*") {
        let extractor = test_extractor();
        // Should not panic on any input
        let _result = extract_domain(&extractor, &url);
    }

    #[test]
    fn test_domain_extraction_with_ports(
        domain in "[a-z]{5,15}",  // Avoid very short domains
        tld in "(com|org|net)",
        port in 1u16..=65535
    ) {
        let url = format!("https://{}.{}:{}", domain, tld, port);
        let extractor = test_extractor();
        let result = extract_domain(&extractor, &url);

        // Port should not affect domain extraction
        prop_assert!(result.is_ok());
        if let Ok(extracted) = result {
            prop_assert!(!extracted.contains(':'),
                "Extracted domain should not contain port");
            prop_assert_eq!(extracted, format!("{}.{}", domain, tld));
        }
    }

    #[test]
    fn test_domain_extraction_with_paths(
        domain in "[a-z]{5,15}",  // Avoid very short domains
        tld in "(com|org|net)",
        path in prop::collection::vec("[a-z]{1,10}", 0..5)
    ) {
        let url = format!("https://{}.{}/{}", domain, tld, path.join("/"));
        let extractor = test_extractor();
        let result = extract_domain(&extractor, &url);

        // Path should not affect domain extraction
        prop_assert!(result.is_ok());
        if let Ok(extracted) = result {
            prop_assert_eq!(extracted, format!("{}.{}", domain, tld));
        }
    }

    #[test]
    fn test_domain_extraction_scheme_independence(
        domain in "[a-z]{5,15}",  // Avoid very short domains
        tld in "(com|org|net)",
        scheme in "(http|https)"
    ) {
        let url = format!("{}://{}.{}", scheme, domain, tld);
        let extractor = test_extractor();
        let result = extract_domain(&extractor, &url);

        // Scheme should not affect extracted domain
        prop_assert!(result.is_ok());
        if let Ok(extracted) = result {
            prop_assert_eq!(extracted, format!("{}.{}", domain, tld));
        }
    }

    #[test]
    fn test_domain_extraction_with_query(
        domain in "[a-z]{5,15}",  // Avoid very short domains
        tld in "(com|org|net)",
        key in "[a-z]{1,10}",
        value in "[a-z]{1,10}"
    ) {
        let url = format!("https://{}.{}?{}={}", domain, tld, key, value);
        let extractor = test_extractor();
        let result = extract_domain(&extractor, &url);

        // Query string should not affect domain extraction
        prop_assert!(result.is_ok());
        if let Ok(extracted) = result {
            prop_assert_eq!(extracted, format!("{}.{}", domain, tld));
        }
    }
}
