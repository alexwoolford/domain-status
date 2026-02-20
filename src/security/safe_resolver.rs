//! SSRF-safe DNS resolver for reqwest.
//!
//! Implements `reqwest::dns::Resolve` by delegating to the system resolver and
//! then validating that every returned IP is public. Connections to private,
//! loopback, or link-local addresses are rejected *before* reqwest opens a TCP
//! socket, closing the TOCTOU / DNS-rebinding gap.

use once_cell::sync::Lazy;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Concurrency limiter for DNS lookups (prevent resource exhaustion)
static DNS_SEMAPHORE: Lazy<Arc<Semaphore>> = Lazy::new(|| Arc::new(Semaphore::new(64)));

/// A DNS resolver that rejects private/loopback/link-local IPs.
///
/// Wraps `tokio::net::lookup_host` (system resolver) and filters out
/// any addresses that would constitute an SSRF risk. If *all* resolved
/// IPs are private, the resolution fails with an error.
#[derive(Debug, Clone)]
pub struct SafeResolver;

impl Resolve for SafeResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let _permit = DNS_SEMAPHORE
                .acquire()
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

            let host = format!("{}:0", name.as_str());
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&host)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                .collect();

            let safe_addrs: Vec<SocketAddr> = addrs
                .into_iter()
                .filter(|addr| is_public_ip(addr.ip()))
                .collect();

            if safe_addrs.is_empty() {
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "SSRF blocked: all resolved IPs for '{}' are private/reserved",
                        name.as_str()
                    ),
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            let addrs: Addrs = Box::new(safe_addrs.into_iter());
            Ok(addrs)
        })
    }
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_ipv4(v4),
        IpAddr::V6(v6) => is_public_ipv6(v6),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    // Loopback 127.0.0.0/8
    if o[0] == 127 {
        return false;
    }
    // Private 10.0.0.0/8
    if o[0] == 10 {
        return false;
    }
    // Private 172.16.0.0/12
    if o[0] == 172 && (16..=31).contains(&o[1]) {
        return false;
    }
    // Private 192.168.0.0/16
    if o[0] == 192 && o[1] == 168 {
        return false;
    }
    // Link-local 169.254.0.0/16
    if o[0] == 169 && o[1] == 254 {
        return false;
    }
    // This-network 0.0.0.0/8
    if o[0] == 0 {
        return false;
    }
    // Multicast 224.0.0.0/4
    if (224..=239).contains(&o[0]) {
        return false;
    }
    // Reserved 240.0.0.0/4
    if o[0] >= 240 {
        return false;
    }
    true
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    // ::1 loopback
    if s == [0, 0, 0, 0, 0, 0, 0, 1] {
        return false;
    }
    // fc00::/7 unique-local
    if (s[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    // fe80::/10 link-local
    if (s[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    // ff00::/8 multicast
    if s[0] & 0xff00 == 0xff00 {
        return false;
    }
    // :: unspecified
    if s == [0; 8] {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_ipv4() {
        assert!(is_public_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(is_public_ipv4(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(is_public_ipv4(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[test]
    fn test_private_ipv4() {
        assert!(!is_public_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_public_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_public_ipv4(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(!is_public_ipv4(Ipv4Addr::new(172, 31, 255, 255)));
        assert!(!is_public_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_public_ipv4(Ipv4Addr::new(169, 254, 1, 1)));
        assert!(!is_public_ipv4(Ipv4Addr::new(0, 0, 0, 0)));
        assert!(!is_public_ipv4(Ipv4Addr::new(224, 0, 0, 1)));
        assert!(!is_public_ipv4(Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn test_public_ipv6() {
        assert!(is_public_ipv6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        )));
        assert!(is_public_ipv6(Ipv6Addr::new(
            0x2607, 0xf8b0, 0x4004, 0x800, 0, 0, 0, 0x200e
        )));
    }

    #[test]
    fn test_private_ipv6() {
        assert!(!is_public_ipv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
        assert!(!is_public_ipv6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)));
        assert!(!is_public_ipv6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
        assert!(!is_public_ipv6(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 1)));
        assert!(!is_public_ipv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)));
    }

    #[tokio::test]
    async fn test_safe_resolver_public_domain() {
        use std::str::FromStr;
        let resolver = SafeResolver;
        let name = Name::from_str("example.com").unwrap();
        let result = resolver.resolve(name).await;
        assert!(result.is_ok(), "Public domain should resolve successfully");
        let addrs: Vec<SocketAddr> = result.unwrap().collect();
        assert!(!addrs.is_empty(), "Should return at least one address");
        for addr in &addrs {
            assert!(
                is_public_ip(addr.ip()),
                "All returned IPs should be public: {}",
                addr.ip()
            );
        }
    }

    #[tokio::test]
    async fn test_safe_resolver_localhost_blocked() {
        use std::str::FromStr;
        let resolver = SafeResolver;
        let name = Name::from_str("localhost").unwrap();
        let result = resolver.resolve(name).await;
        assert!(
            result.is_err(),
            "localhost should be blocked (resolves to 127.0.0.1)"
        );
    }
}
