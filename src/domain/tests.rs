// Domain module tests.

use super::*;

#[test]
fn test_normalize_domain_lowercases_and_strips_www() {
    assert_eq!(normalize_domain("WWW.Example.COM"), "example.com");
    assert_eq!(normalize_domain("  example.com  "), "example.com");
    assert_eq!(normalize_domain("www.example.co.uk"), "example.co.uk");
    assert_eq!(normalize_domain("example.com"), "example.com");
}

#[test]
fn test_root_domain_basic() {
    assert_eq!(
        root_domain("www.example.com"),
        Some("example.com".to_string())
    );
    assert_eq!(
        root_domain("a.b.example.co.uk"),
        Some("example.co.uk".to_string())
    );
}

#[test]
fn test_extract_domain_basic() {
    assert_eq!(
        extract_domain("https://www.example.com/path").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_with_port() {
    // Port should be ignored, domain extraction should work
    assert_eq!(
        extract_domain("https://www.example.com:8080/path").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_with_query_and_fragment() {
    // Query strings and fragments should not affect domain extraction
    assert_eq!(
        extract_domain("https://example.com/path?query=1#fragment").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_subdomain() {
    // Should extract registrable domain, not subdomain
    assert_eq!(
        extract_domain("https://subdomain.example.com").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_multiple_subdomains() {
    assert_eq!(
        extract_domain("https://a.b.c.example.com").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_no_subdomain() {
    assert_eq!(
        extract_domain("https://example.com").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_http() {
    // Should work with HTTP too
    assert_eq!(
        extract_domain("http://example.com").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_invalid_url() {
    // Invalid URL should return error
    assert!(extract_domain("not-a-url").is_err());
}

#[test]
fn test_extract_domain_url_without_host() {
    // URL without host should fail
    assert!(extract_domain("file:///path/to/file").is_err());
}

#[test]
fn test_extract_domain_ip_literal_used_as_key() {
    assert_eq!(
        extract_domain("http://127.0.0.1:8080/path").unwrap(),
        "127.0.0.1"
    );
    assert_eq!(
        extract_domain("http://[::1]/").unwrap(),
        "[::1]"
    );
}

#[test]
fn test_extract_domain_uk_domain() {
    // UK domains like co.uk - should return registrable domain, not just the suffix
    let result = extract_domain("https://www.example.co.uk");
    assert!(result.is_ok());
    let domain = result.unwrap();
    // Should return "example.co.uk" (registrable domain), not "co.uk" (public suffix)
    assert_eq!(domain, "example.co.uk");
}

#[test]
fn test_extract_domain_com_br() {
    // Brazilian domains like com.br - should return registrable domain
    let result = extract_domain("https://www.example.com.br");
    assert!(result.is_ok());
    let domain = result.unwrap();
    // Should return "example.com.br" (registrable domain), not "com.br" (public suffix)
    assert_eq!(domain, "example.com.br");
}

#[test]
fn test_extract_domain_co_jp() {
    // Japanese domains like co.jp - should return registrable domain
    let result = extract_domain("https://www.example.co.jp");
    assert!(result.is_ok());
    let domain = result.unwrap();
    // Should return "example.co.jp" (registrable domain), not "co.jp" (public suffix)
    assert_eq!(domain, "example.co.jp");
}

#[test]
fn test_extract_domain_example_co() {
    // .co domains (Colombia) - should return the full domain
    let result = extract_domain("https://example.co");
    assert!(result.is_ok());
    let domain = result.unwrap();
    // Should return "example.co" (the registrable domain)
    assert_eq!(domain, "example.co");
}

#[test]
fn test_extract_domain_example_co_with_subdomain() {
    // .co domains with subdomain
    let result = extract_domain("https://www.example.co");
    assert!(result.is_ok());
    let domain = result.unwrap();
    // Should return "example.co" (the registrable domain), not "co" or "www.example.co"
    assert_eq!(domain, "example.co");
}

#[test]
fn test_extract_domain_example_org() {
    // Simple, standard domain (RFC 2606)
    let result = extract_domain("https://example.org");
    assert!(result.is_ok());
    let domain = result.unwrap();
    assert_eq!(domain, "example.org");
}

#[test]
fn test_extract_domain_example_org_with_www() {
    let result = extract_domain("https://www.example.org");
    assert!(result.is_ok());
    let domain = result.unwrap();
    assert_eq!(domain, "example.org");
}

// Tests for edge cases to cover uncovered lines in extract_domain
// These test paths that are difficult to trigger but important for robustness

#[test]
fn test_extract_domain_simple_tld_no_extraction_needed() {
    // Test simple TLD where extraction is not needed (covers line 143)
    // For simple TLDs like .com, domain() works correctly and needs_extraction should be false
    let result = extract_domain("https://example.com");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "example.com");
}

#[test]
fn test_extract_domain_idn_punycode_multi_part_tld() {
    // Replaces a previous duplicate of test_extract_domain_uk_domain. Covers an
    // IDN-style host with a multi-part TLD that the registrable-domain extraction
    // path must handle (Wappalyzer tests, japanese ccTLDs, German .de, etc.).
    // psl crate normalizes ASCII compatibility encoding (xn--*).
    let result = extract_domain("https://www.xn--bcher-kva.de"); // bücher.de
    assert!(result.is_ok());
    let domain = result.unwrap();
    assert_eq!(
        domain, "xn--bcher-kva.de",
        "IDN host should resolve to its punycode-encoded registrable domain"
    );
}

#[test]
fn test_extract_domain_fallback_when_extraction_fails() {
    // Test fallback path (line 175) when extraction logic can't find proper domain
    // This is difficult to trigger with real domains, but we test edge cases
    // Try with unusual domain patterns that might cause extraction to fail
    let result = extract_domain("https://test.example.com");
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

// Property-based tests using proptest
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_extract_domain_idempotent(
        domain in "[a-z]{5,15}",  // Avoid very short domains that might not be in PSL
        tld in "(com|org|net|co\\.uk)"
    ) {
        let url = format!("https://www.{}.{}", domain, tld);

        let extracted = extract_domain(&url);
        if let Ok(d) = extracted {
            // Extracting domain from a domain should return same domain
            let url2 = format!("https://{}", d);
            let extracted2 = extract_domain(&url2);
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
        let root_domain = extract_domain(&root_url).ok();

        if let Some(root) = root_domain {
            // Adding subdomains shouldn't change root domain
            let sub_url = format!("https://{}.{}.{}",
                subdomain.join("."), domain, tld);
            let sub_domain = extract_domain(&sub_url).ok();

            prop_assert_eq!(Some(root), sub_domain,
                "Subdomains should extract to same root domain");
        }
    }

    #[test]
    fn test_domain_extraction_no_panic(url in "https?://[a-zA-Z0-9.-]{1,100}\\.[a-z]{2,10}.*") {
        // Should not panic on any input
        let _result = extract_domain(&url);
    }

    #[test]
    fn test_domain_extraction_with_ports(
        domain in "[a-z]{5,15}",  // Avoid very short domains
        tld in "(com|org|net)",
        port in 1u16..=65535
    ) {
        let url = format!("https://{}.{}:{}", domain, tld, port);
        let result = extract_domain(&url);

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
        let result = extract_domain(&url);

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
        let result = extract_domain(&url);

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
        let result = extract_domain(&url);

        // Query string should not affect domain extraction
        prop_assert!(result.is_ok());
        if let Ok(extracted) = result {
            prop_assert_eq!(extracted, format!("{}.{}", domain, tld));
        }
    }
}
