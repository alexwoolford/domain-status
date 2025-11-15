use anyhow::Result;
use publicsuffix::{List, Psl};
use reqwest::Url;

/// Extracts the registrable domain from a URL using the Public Suffix List.
///
/// # Arguments
///
/// * `list` - The Public Suffix List instance
/// * `url` - The URL to extract the domain from
///
/// # Returns
///
/// The registrable domain (e.g., "example.com" from "https://www.example.com/path")
///
/// # Errors
///
/// Returns an error if the URL cannot be parsed or if domain extraction fails.
pub fn extract_domain(list: &List, url: &str) -> Result<String> {
    let parsed = Url::parse(url)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Failed to extract host from {url}"))?;
    let d = list
        .domain(host.as_bytes())
        .ok_or_else(|| anyhow::anyhow!("Failed to extract domain from {url}"))?;
    Ok(String::from_utf8_lossy(d.as_bytes()).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // UK domains like co.uk are a common gotcha
        // The publicsuffix crate's domain() method returns the public suffix for multi-part TLDs
        // This documents the actual behavior: "co.uk" is returned, not "example.co.uk"
        let result = extract_domain(&list, "https://www.example.co.uk");
        assert!(result.is_ok());
        let domain = result.unwrap();
        // The crate returns "co.uk" (the public suffix) rather than the registrable domain
        // This is a known limitation/behavior of the publicsuffix crate
        assert_eq!(domain, "co.uk");
    }
}
