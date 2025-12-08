//! URL validation and SSRF protection.
//!
//! This module provides functions to validate URLs and prevent SSRF (Server-Side Request Forgery)
//! attacks by blocking access to:
//! - Private/internal IP addresses (RFC 1918, RFC 4193, etc.)
//! - Localhost addresses
//! - Non-HTTP/HTTPS schemes (file://, ftp://, etc.)
//! - Link-local addresses
//!
//! This is critical for redirect handling and network downloads to prevent attackers from
//! redirecting requests to internal services or downloading malicious content.

use anyhow::{Context, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
use url::Url;

/// Validates that a URL is safe to fetch (SSRF protection).
///
/// This function checks:
/// - URL uses http:// or https:// scheme
/// - Host is not a private/internal IP address
/// - Host is not localhost
/// - Host is not a link-local address
///
/// # Arguments
///
/// * `url_str` - The URL string to validate
///
/// # Returns
///
/// `Ok(())` if the URL is safe, `Err` with a descriptive message if unsafe.
///
/// # Examples
///
/// ```
/// use domain_status::security::url_validation::validate_url_safe;
///
/// // Safe URLs
/// assert!(validate_url_safe("https://example.com").is_ok());
/// assert!(validate_url_safe("http://192.0.2.1").is_ok()); // Public test IP
///
/// // Unsafe URLs (SSRF risk)
/// assert!(validate_url_safe("http://127.0.0.1").is_err());
/// assert!(validate_url_safe("http://192.168.1.1").is_err());
/// assert!(validate_url_safe("file:///etc/passwd").is_err());
/// ```
pub fn validate_url_safe(url_str: &str) -> Result<()> {
    let url = Url::parse(url_str).with_context(|| format!("Failed to parse URL: {}", url_str))?;

    // Only allow http:// and https:// schemes
    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(anyhow::anyhow!(
                "Unsafe URL scheme '{}' (only http:// and https:// allowed): {}",
                scheme,
                url_str
            ));
        }
    }

    // Check host
    if let Some(host) = url.host() {
        match host {
            url::Host::Domain(domain) => {
                // Check for localhost variants
                if is_localhost_domain(domain) {
                    return Err(anyhow::anyhow!(
                        "Unsafe URL: localhost domain '{}' is not allowed: {}",
                        domain,
                        url_str
                    ));
                }
            }
            url::Host::Ipv4(ip) => {
                if is_private_ipv4(ip) {
                    return Err(anyhow::anyhow!(
                        "Unsafe URL: private IPv4 address '{}' is not allowed: {}",
                        ip,
                        url_str
                    ));
                }
            }
            url::Host::Ipv6(ip) => {
                if is_private_ipv6(ip) {
                    return Err(anyhow::anyhow!(
                        "Unsafe URL: private IPv6 address '{}' is not allowed: {}",
                        ip,
                        url_str
                    ));
                }
            }
        }
    } else {
        return Err(anyhow::anyhow!("URL has no host component: {}", url_str));
    }

    Ok(())
}

/// Checks if an IPv4 address is private/internal (RFC 1918).
///
/// Private ranges:
/// - 10.0.0.0/8
/// - 172.16.0.0/12
/// - 192.168.0.0/16
/// - 127.0.0.0/8 (loopback)
/// - 169.254.0.0/16 (link-local)
/// - 0.0.0.0/8 (this network)
/// - 224.0.0.0/4 (multicast)
/// - 240.0.0.0/4 (reserved)
fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();

    // 127.0.0.0/8 (loopback)
    if octets[0] == 127 {
        return true;
    }

    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }

    // 172.16.0.0/12
    if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
        return true;
    }

    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }

    // 169.254.0.0/16 (link-local)
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }

    // 0.0.0.0/8 (this network)
    if octets[0] == 0 {
        return true;
    }

    // 224.0.0.0/4 (multicast)
    if octets[0] >= 224 && octets[0] <= 239 {
        return true;
    }

    // 240.0.0.0/4 (reserved)
    if octets[0] >= 240 {
        return true;
    }

    false
}

/// Checks if an IPv6 address is private/internal (RFC 4193, RFC 4291).
///
/// Private ranges:
/// - ::1 (loopback)
/// - fc00::/7 (unique local addresses)
/// - fe80::/10 (link-local)
/// - ff00::/8 (multicast)
fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();

    // ::1 (loopback)
    if segments == [0, 0, 0, 0, 0, 0, 0, 1] {
        return true;
    }

    // fc00::/7 (unique local addresses)
    if (segments[0] & 0xfe00) == 0xfc00 {
        return true;
    }

    // fe80::/10 (link-local)
    if (segments[0] & 0xffc0) == 0xfe80 {
        return true;
    }

    // ff00::/8 (multicast)
    if segments[0] & 0xff00 == 0xff00 {
        return true;
    }

    false
}

/// Checks if a domain name is a localhost variant.
fn is_localhost_domain(domain: &str) -> bool {
    let domain_lower = domain.to_lowercase();
    matches!(
        domain_lower.as_str(),
        "localhost" | "localhost." | "localhost.localdomain" | "localhost.localdomain."
    ) || domain_lower.ends_with(".localhost")
        || domain_lower.ends_with(".localhost.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_url_safe_public_urls() {
        // Public URLs should be safe
        assert!(validate_url_safe("https://example.com").is_ok());
        assert!(validate_url_safe("http://example.com").is_ok());
        assert!(validate_url_safe("https://subdomain.example.com").is_ok());
        assert!(validate_url_safe("https://example.com:8080").is_ok());
        assert!(validate_url_safe("https://example.com/path?query=value").is_ok());
    }

    #[test]
    fn test_validate_url_safe_public_ips() {
        // Public IPs should be safe (RFC 5737 test addresses)
        assert!(validate_url_safe("http://192.0.2.1").is_ok());
        assert!(validate_url_safe("http://198.51.100.1").is_ok());
        assert!(validate_url_safe("http://203.0.113.1").is_ok());
        assert!(validate_url_safe("http://8.8.8.8").is_ok()); // Google DNS
        assert!(validate_url_safe("http://1.1.1.1").is_ok()); // Cloudflare DNS
    }

    #[test]
    fn test_validate_url_safe_private_ipv4() {
        // Private IPv4 addresses should be blocked
        assert!(validate_url_safe("http://127.0.0.1").is_err());
        assert!(validate_url_safe("http://127.0.0.1:8080").is_err());
        assert!(validate_url_safe("http://localhost").is_err());
        assert!(validate_url_safe("http://192.168.1.1").is_err());
        assert!(validate_url_safe("http://10.0.0.1").is_err());
        assert!(validate_url_safe("http://172.16.0.1").is_err());
        assert!(validate_url_safe("http://172.31.255.255").is_err());
        assert!(validate_url_safe("http://169.254.1.1").is_err()); // Link-local
        assert!(validate_url_safe("http://0.0.0.0").is_err());
        assert!(validate_url_safe("http://224.0.0.1").is_err()); // Multicast
        assert!(validate_url_safe("http://255.255.255.255").is_err()); // Reserved
    }

    #[test]
    fn test_validate_url_safe_private_ipv6() {
        // Private IPv6 addresses should be blocked
        assert!(validate_url_safe("http://[::1]").is_err()); // Loopback
        assert!(validate_url_safe("http://[fc00::1]").is_err()); // Unique local
        assert!(validate_url_safe("http://[fe80::1]").is_err()); // Link-local
        assert!(validate_url_safe("http://[ff00::1]").is_err()); // Multicast
    }

    #[test]
    fn test_validate_url_safe_localhost_domains() {
        // Localhost domain variants should be blocked
        assert!(validate_url_safe("http://localhost").is_err());
        assert!(validate_url_safe("http://localhost:8080").is_err());
        assert!(validate_url_safe("http://localhost.localdomain").is_err());
        assert!(validate_url_safe("http://subdomain.localhost").is_err());
        assert!(validate_url_safe("http://subdomain.localhost:8080").is_err());
    }

    #[test]
    fn test_validate_url_safe_unsafe_schemes() {
        // Non-HTTP/HTTPS schemes should be blocked
        assert!(validate_url_safe("file:///etc/passwd").is_err());
        assert!(validate_url_safe("ftp://example.com").is_err());
        assert!(validate_url_safe("gopher://example.com").is_err());
        assert!(validate_url_safe("javascript:alert(1)").is_err());
        assert!(validate_url_safe("data:text/html,<script>alert(1)</script>").is_err());
    }

    #[test]
    fn test_validate_url_safe_invalid_urls() {
        // Invalid URLs should return errors
        assert!(validate_url_safe("not-a-url").is_err());
        assert!(validate_url_safe("").is_err());
    }

    #[test]
    fn test_is_private_ipv4() {
        // Private ranges
        assert!(is_private_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(172, 31, 255, 255)));
        assert!(is_private_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(169, 254, 1, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(is_private_ipv4(Ipv4Addr::new(224, 0, 0, 1)));
        assert!(is_private_ipv4(Ipv4Addr::new(255, 255, 255, 255)));

        // Public IPs
        assert!(!is_private_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ipv4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_private_ipv4(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!is_private_ipv4(Ipv4Addr::new(203, 0, 113, 1)));
    }

    #[test]
    fn test_is_private_ipv6() {
        // Private ranges
        assert!(is_private_ipv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))); // ::1
        assert!(is_private_ipv6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))); // fc00::/7
        assert!(is_private_ipv6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))); // fe80::/10
        assert!(is_private_ipv6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 1))); // ff00::/8

        // Public IPs
        assert!(!is_private_ipv6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        ))); // 2001:db8::1
    }

    #[test]
    fn test_is_localhost_domain() {
        assert!(is_localhost_domain("localhost"));
        assert!(is_localhost_domain("localhost."));
        assert!(is_localhost_domain("localhost.localdomain"));
        assert!(is_localhost_domain("subdomain.localhost"));
        assert!(is_localhost_domain("subdomain.localhost."));

        assert!(!is_localhost_domain("example.com"));
        assert!(!is_localhost_domain("localhost.example.com"));
    }
}
