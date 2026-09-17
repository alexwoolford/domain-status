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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

/// Validates that a URL is safe to fetch (SSRF protection).
///
/// This function checks:
/// - URL uses http:// or https:// scheme
/// - Host is not a private/internal IP address
/// - Host is not localhost
/// - Host is not a link-local address
///
/// RFC 5737 documentation nets (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
/// are treated as unsafe, as are RFC 3849 IPv6 documentation addresses (`2001:db8::/32`).
///
/// # Arguments
///
/// * `url_str` - The URL string to validate
///
/// # Returns
///
/// `Ok(())` if the URL is safe, `Err` with a descriptive message if unsafe.
pub fn validate_url_safe(url_str: &str) -> Result<()> {
    let url = Url::parse(url_str).with_context(|| format!("Failed to parse URL: {url_str}"))?;

    // Only allow http:// and https:// schemes
    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(anyhow::anyhow!(
                "Unsafe URL scheme '{scheme}' (only http:// and https:// allowed): {url_str}"
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
                        "Unsafe URL: localhost domain '{domain}' is not allowed: {url_str}"
                    ));
                }
            }
            url::Host::Ipv4(ip) => {
                if is_private_ipv4(ip) {
                    return Err(anyhow::anyhow!(
                        "Unsafe URL: private IPv4 address '{ip}' is not allowed: {url_str}"
                    ));
                }
            }
            url::Host::Ipv6(ip) => {
                if is_private_ipv6(ip) {
                    return Err(anyhow::anyhow!(
                        "Unsafe URL: private IPv6 address '{ip}' is not allowed: {url_str}"
                    ));
                }
            }
        }
    } else {
        return Err(anyhow::anyhow!("URL has no host component: {url_str}"));
    }

    Ok(())
}

/// Single source of truth for private/reserved IPv4 ranges (SSRF protection).
///
/// Uses stable `Ipv4Addr` predicates plus ranges std does not yet expose:
/// entire `0.0.0.0/8`, CGNAT `100.64.0.0/10`, benchmarking `198.18.0.0/15`,
/// IETF Protocol Assignments `192.0.0.0/24`, and reserved `240.0.0.0/4`.
pub(crate) fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    if ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
    {
        return true;
    }
    let octets = ip.octets();
    octets[0] == 0
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 198 && matches!(octets[1], 18 | 19))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || octets[0] >= 240
}

/// Returns true if the IP is private/reserved (SSRF-unsafe). Single source of truth for both
/// URL validation and the safe DNS resolver.
pub(crate) fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => is_private_ipv6(v6),
    }
}

/// Checks if an IPv6 address is private/internal (RFC 4193, RFC 4291, RFC 3849).
///
/// Private / non-routable ranges:
/// - IPv4-mapped (`::ffff:x.x.x.x`) and deprecated IPv4-compatible (`::x.x.x.x`)
///   addresses, classified via the IPv4 check
/// - `::` unspecified, `::1` loopback
/// - `fc00::/7` unique local, `fe80::/10` link-local, `ff00::/8` multicast
/// - `2001:db8::/32` documentation (RFC 3849)
pub(crate) fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(ipv4);
    }
    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || ip.is_multicast()
    {
        return true;
    }
    let segments = ip.segments();
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return true;
    }
    // Deprecated IPv4-compatible (`::10.0.0.1`); mapped addresses already returned above.
    if let Some(ipv4) = ip.to_ipv4() {
        return is_private_ipv4(ipv4);
    }
    false
}

/// Returns a reqwest redirect policy that validates each redirect target with SSRF checks.
///
/// Use this for clients that need to follow redirects (e.g. GitHub CDN, `MaxMind` downloads)
/// while blocking redirects to private/reserved IPs. Prefer this over `Policy::none()` so
/// legitimate redirects still work; redirects to internal IPs cause the attempt to stop.
pub fn ssrf_safe_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        let url = attempt.url().as_str();
        match validate_url_safe(url) {
            Ok(()) => attempt.follow(),
            Err(err) => {
                log::warn!("SSRF-safe redirect stopped: {err}");
                attempt.stop()
            }
        }
    })
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

    /// `(ip, is_private, label)` — source of truth for IP classification.
    const PRIVATE_IP_CASES: &[(&str, bool, &str)] = &[
        ("8.8.8.8", false, "Google DNS"),
        ("1.1.1.1", false, "Cloudflare DNS"),
        ("93.184.216.34", false, "example.com A"),
        ("172.15.255.255", false, "just below RFC1918 172.16/12"),
        ("172.16.0.0", true, "RFC1918 172.16/12 start"),
        ("172.31.255.255", true, "RFC1918 172.16/12 end"),
        ("100.63.255.255", false, "just below CGNAT"),
        ("100.64.0.0", true, "CGNAT start"),
        ("10.0.0.1", true, "RFC1918 10/8"),
        ("192.168.1.1", true, "RFC1918 192.168/16"),
        ("127.0.0.1", true, "loopback"),
        ("169.254.1.1", true, "link-local"),
        ("0.0.0.0", true, "unspecified"),
        ("0.1.2.3", true, "0/8 this-network"),
        ("224.0.0.1", true, "multicast"),
        ("255.255.255.255", true, "broadcast/reserved"),
        ("192.0.2.1", true, "RFC5737 TEST-NET-1"),
        ("198.51.100.1", true, "RFC5737 TEST-NET-2"),
        ("203.0.113.1", true, "RFC5737 TEST-NET-3"),
        ("198.18.0.1", true, "benchmarking"),
        ("192.0.0.1", true, "IETF Protocol Assignments"),
        ("192.0.1.1", false, "just above 192.0.0.0/24"),
        ("::ffff:8.8.8.8", false, "IPv4-mapped public"),
        ("::ffff:10.0.0.1", true, "IPv4-mapped private"),
        ("::10.0.0.1", true, "IPv4-compatible private"),
        ("::8.8.8.8", false, "IPv4-compatible public"),
        ("::1", true, "IPv6 loopback"),
        ("::", true, "IPv6 unspecified"),
        ("fc00::1", true, "unique local"),
        ("fe80::1", true, "IPv6 link-local"),
        ("ff00::1", true, "IPv6 multicast"),
        ("2001:db8::1", true, "RFC3849 documentation"),
        ("2607:f8b0:4004:800::200e", false, "public IPv6"),
    ];

    #[test]
    fn test_is_private_ip_table() {
        for &(ip_str, expect_private, label) in PRIVATE_IP_CASES {
            let ip: IpAddr = ip_str.parse().unwrap_or_else(|e| {
                panic!("fixture {label:?} ({ip_str}) must parse: {e}");
            });
            assert_eq!(
                is_private_ip(ip),
                expect_private,
                "{label}: {ip} expected private={expect_private}"
            );
        }
    }

    #[test]
    fn test_validate_url_safe_public_urls() {
        assert!(validate_url_safe("https://example.com").is_ok());
        assert!(validate_url_safe("http://example.com").is_ok());
        assert!(validate_url_safe("https://example.com:8080/path?query=value").is_ok());
        assert!(validate_url_safe("http://8.8.8.8").is_ok());
    }

    #[test]
    fn test_validate_url_safe_documentation_ip_error() {
        let err = validate_url_safe("http://192.0.2.1")
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "Unsafe URL: private IPv4 address '192.0.2.1' is not allowed: http://192.0.2.1"
        );
    }

    #[test]
    fn test_validate_url_safe_bad_scheme_error() {
        let err = validate_url_safe("file:///etc/passwd")
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "Unsafe URL scheme 'file' (only http:// and https:// allowed): file:///etc/passwd"
        );
        assert!(validate_url_safe("ftp://example.com").is_err());
        assert!(validate_url_safe("javascript:alert(1)").is_err());
    }

    #[test]
    fn test_validate_url_safe_localhost_name_error() {
        let err = validate_url_safe("http://localhost")
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "Unsafe URL: localhost domain 'localhost' is not allowed: http://localhost"
        );
        assert!(validate_url_safe("http://localhost.localdomain").is_err());
        assert!(validate_url_safe("http://subdomain.localhost").is_err());
        assert!(validate_url_safe("https://example.com").is_ok());
    }

    #[test]
    fn test_validate_url_safe_unparseable() {
        assert!(validate_url_safe("not-a-url").is_err());
        assert!(validate_url_safe("").is_err());
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
