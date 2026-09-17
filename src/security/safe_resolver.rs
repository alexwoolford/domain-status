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

            let safe_addrs = filter_public_socket_addrs(lookup.iter(), name.as_str())?;
            let addrs: Addrs = Box::new(safe_addrs.into_iter());
            Ok(addrs)
        })
    }
}

/// Filters resolved IPs to public addresses only.
///
/// Returns an error when every answer is private/reserved — the DNS-rebinding
/// failure mode where a later lookup yields only internal addresses.
pub(crate) fn filter_public_socket_addrs(
    ips: impl IntoIterator<Item = IpAddr>,
    name: &str,
) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    let safe_addrs: Vec<SocketAddr> = ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, 0))
        .filter(|addr| is_public_ip(addr.ip()))
        .collect();

    if safe_addrs.is_empty() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("SSRF blocked: all resolved IPs for '{name}' are private/reserved"),
        )) as Box<dyn std::error::Error + Send + Sync>);
    }

    Ok(safe_addrs)
}

/// Public iff not private; uses shared logic from `url_validation` (single source of truth).
pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    !url_validation::is_private_ip(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    #[test]
    fn test_is_public_ip_negates_private() {
        let public = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let private = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(is_public_ip(public));
        assert!(!is_public_ip(private));
        assert_eq!(is_public_ip(public), !url_validation::is_private_ip(public));
        assert_eq!(
            is_public_ip(private),
            !url_validation::is_private_ip(private)
        );
    }

    #[test]
    fn test_filter_keeps_only_public_from_mixed_answers() {
        let ips = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        ];
        let addrs = filter_public_socket_addrs(ips, "mixed.example").expect("public present");
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].ip(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_filter_rejects_private_only_answers() {
        let ips = [
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        ];
        let err = filter_public_socket_addrs(ips, "evil.example").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("SSRF blocked") && msg.contains("evil.example"),
            "unexpected error: {msg}"
        );
    }

    /// Models DNS rebinding: first lookup returns a public IP (allowed), a later
    /// lookup for the same name returns only private/metadata IPs (blocked).
    #[test]
    fn test_filter_rebinding_style_second_lookup_private_only() {
        let first = [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))];
        let first_addrs =
            filter_public_socket_addrs(first, "rebind.example").expect("first lookup public");
        assert_eq!(first_addrs.len(), 1);

        let second = [
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        ];
        assert!(
            filter_public_socket_addrs(second, "rebind.example").is_err(),
            "second (rebinding) lookup must be blocked"
        );
    }

    #[tokio::test]
    #[ignore = "live DNS; run with --ignored"]
    async fn test_safe_resolver_public_domain() {
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
}
