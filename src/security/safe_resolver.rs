//! SSRF-safe DNS resolver for reqwest.
//!
//! Implements `reqwest::dns::Resolve` by delegating to the configured hickory
//! resolver (with timeouts) and then validating that every returned IP is public.
//! Connections to private, loopback, or link-local addresses are rejected *before*
//! reqwest opens a TCP socket, closing the TOCTOU / DNS-rebinding gap.

use super::url_validation;
use hickory_resolver::TokioResolver;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

/// A DNS resolver that rejects private/loopback/link-local IPs.
///
/// Uses the configured [`TokioResolver`] (from `init_resolver()`) so DNS timeouts
/// (e.g. 3s) are respected during HTTP requests. Resolved IPs are filtered so only
/// public addresses are returned; if *all* resolved IPs are private, resolution
/// fails with an error.
#[derive(Debug, Clone)]
pub struct SafeResolver {
    /// Shared hickory resolver (same timeout config as used elsewhere).
    pub(crate) resolver: Arc<TokioResolver>,
}

impl SafeResolver {
    /// Creates a `SafeResolver` that uses the given hickory resolver for lookups.
    pub fn new(resolver: Arc<TokioResolver>) -> Self {
        Self { resolver }
    }
}

impl Resolve for SafeResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = Arc::clone(&self.resolver);
        Box::pin(async move {
            let lookup = resolver
                .lookup_ip(name.as_str())
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

            let safe_addrs: Vec<SocketAddr> = lookup
                .iter()
                .map(|ip| SocketAddr::new(ip, 0))
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

/// Public iff not private; uses shared logic from `url_validation` (single source of truth).
pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    !url_validation::is_private_ip(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_public_ipv4() {
        assert!(is_public_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(is_public_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(is_public_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
    }

    #[test]
    fn test_private_ipv4() {
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))));
        assert!(!is_public_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    }

    #[test]
    fn test_public_ipv6() {
        assert!(is_public_ip(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        ))));
        assert!(is_public_ip(IpAddr::V6(Ipv6Addr::new(
            0x2607, 0xf8b0, 0x4004, 0x800, 0, 0, 0, 0x200e
        ))));
    }

    #[test]
    fn test_private_ipv6() {
        assert!(!is_public_ip(IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!is_public_ip(IpAddr::V6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!is_public_ip(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!is_public_ip(IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0, 0, 0
        ))));
    }

    #[test]
    fn test_ipv4_mapped_ipv6_blocked() {
        let mapped_loopback = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001);
        assert!(!is_public_ip(IpAddr::V6(mapped_loopback)));
        let mapped_private = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001);
        assert!(!is_public_ip(IpAddr::V6(mapped_private)));
        let mapped_public = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808);
        assert!(is_public_ip(IpAddr::V6(mapped_public)));
    }

    #[tokio::test]
    async fn test_safe_resolver_public_domain() {
        use std::str::FromStr;
        let hickory = crate::initialization::init_resolver().expect("resolver");
        let resolver = SafeResolver::new(hickory);
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
        let hickory = crate::initialization::init_resolver().expect("resolver");
        let resolver = SafeResolver::new(hickory);
        let name = Name::from_str("localhost").unwrap();
        let result = resolver.resolve(name).await;
        assert!(
            result.is_err(),
            "localhost should be blocked (resolves to 127.0.0.1)"
        );
    }
}
