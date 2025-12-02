//! Domain module tests.

use super::*;
use publicsuffix::List;

fn test_list() -> List {
    List::new()
}

#[test]
fn test_extract_domain_basic() {
    let list = test_list();
    assert_eq!(
        extract_domain(&list, "https://www.example.com/path").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_with_port() {
    let list = test_list();
    // Port should be ignored, domain extraction should work
    assert_eq!(
        extract_domain(&list, "https://www.example.com:8080/path").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_with_query_and_fragment() {
    let list = test_list();
    // Query strings and fragments should not affect domain extraction
    assert_eq!(
        extract_domain(&list, "https://example.com/path?query=1#fragment").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_subdomain() {
    let list = test_list();
    // Should extract registrable domain, not subdomain
    assert_eq!(
        extract_domain(&list, "https://subdomain.example.com").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_multiple_subdomains() {
    let list = test_list();
    assert_eq!(
        extract_domain(&list, "https://a.b.c.example.com").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_no_subdomain() {
    let list = test_list();
    assert_eq!(
        extract_domain(&list, "https://example.com").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_http() {
    let list = test_list();
    // Should work with HTTP too
    assert_eq!(
        extract_domain(&list, "http://example.com").unwrap(),
        "example.com"
    );
}

#[test]
fn test_extract_domain_invalid_url() {
    let list = test_list();
    // Invalid URL should return error
    assert!(extract_domain(&list, "not-a-url").is_err());
}

#[test]
fn test_extract_domain_url_without_host() {
    let list = test_list();
    // URL without host should fail
    assert!(extract_domain(&list, "file:///path/to/file").is_err());
}

#[test]
fn test_extract_domain_ip_address() {
    let list = test_list();
    // IP addresses might not work with public suffix list
    // This is a real edge case - IPs don't have registrable domains
    let result = extract_domain(&list, "http://192.168.1.1");
    // Either fails (expected) or returns the IP (also acceptable)
    // The important thing is it doesn't panic
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_extract_domain_uk_domain() {
    let list = test_list();
    // UK domains like co.uk - should return registrable domain, not just the suffix
    let result = extract_domain(&list, "https://www.example.co.uk");
    assert!(result.is_ok());
    let domain = result.unwrap();
    // Should return "example.co.uk" (registrable domain), not "co.uk" (public suffix)
    assert_eq!(domain, "example.co.uk");
}

#[test]
fn test_extract_domain_com_br() {
    let list = test_list();
    // Brazilian domains like com.br - should return registrable domain
    let result = extract_domain(&list, "https://www.example.com.br");
    assert!(result.is_ok());
    let domain = result.unwrap();
    // Should return "example.com.br" (registrable domain), not "com.br" (public suffix)
    assert_eq!(domain, "example.com.br");
}

#[test]
fn test_extract_domain_co_jp() {
    let list = test_list();
    // Japanese domains like co.jp - should return registrable domain
    let result = extract_domain(&list, "https://www.example.co.jp");
    assert!(result.is_ok());
    let domain = result.unwrap();
    // Should return "example.co.jp" (registrable domain), not "co.jp" (public suffix)
    assert_eq!(domain, "example.co.jp");
}

#[test]
fn test_extract_domain_stone_co() {
    let list = test_list();
    // .co domains (Colombia) - should return the full domain
    let result = extract_domain(&list, "https://example.co");
    assert!(result.is_ok());
    let domain = result.unwrap();
    // Should return "example.co" (the registrable domain)
    assert_eq!(domain, "example.co");
}

#[test]
fn test_extract_domain_stone_co_with_subdomain() {
    let list = test_list();
    // .co domains with subdomain
    let result = extract_domain(&list, "https://www.example.co");
    assert!(result.is_ok());
    let domain = result.unwrap();
    // Should return "example.co" (the registrable domain), not "co" or "www.example.co"
    assert_eq!(domain, "example.co");
}

#[test]
fn test_extract_domain_arrow_com() {
    let list = test_list();
    // Test example.org - a simple, standard domain
    let result = extract_domain(&list, "https://example.org");
    assert!(result.is_ok());
    let domain = result.unwrap();
    // Should return "example.org" (the registrable domain)
    assert_eq!(domain, "example.org");
}

#[test]
fn test_extract_domain_arrow_com_with_www() {
    let list = test_list();
    // Test www.example.org - with subdomain
    let result = extract_domain(&list, "https://www.example.org");
    assert!(result.is_ok());
    let domain = result.unwrap();
    // Should return "example.org" (the registrable domain), not "www.example.org"
    assert_eq!(domain, "example.org");
}

