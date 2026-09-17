//! IP address resolution and reverse DNS lookup.

use anyhow::{Error, Result};
use hickory_resolver::TokioResolver;
use std::net::IpAddr;

/// Prefers a public IP when the response contains both public and private
/// addresses, matching [`SafeResolver`](crate::security::safe_resolver::SafeResolver).
#[must_use]
pub(crate) fn prefer_public_ip(ips: impl IntoIterator<Item = IpAddr>) -> Option<IpAddr> {
    let mut first = None;
    for ip in ips {
        if crate::security::safe_resolver::is_public_ip(ip) {
            return Some(ip);
        }
        if first.is_none() {
            first = Some(ip);
        }
    }
    first
}

/// Resolves a hostname to an IP address using DNS.
///
/// Prefers a public IP when the response contains both public and private
/// addresses, so the returned value matches what [`SafeResolver`](crate::security::safe_resolver::SafeResolver)
/// would use for the actual connection.
///
/// # Errors
///
/// Returns an error if DNS resolution fails or no IP addresses are found.
pub async fn resolve_host_to_ip(host: &str, resolver: &TokioResolver) -> Result<String, Error> {
    let response = resolver.lookup_ip(host).await.map_err(Error::new)?;
    prefer_public_ip(response.iter())
        .map(|ip| ip.to_string())
        .ok_or_else(|| Error::msg("No IP addresses found"))
}

/// Performs a reverse DNS lookup (PTR record) for an IP address.
///
/// Returns the reverse DNS name, or `None` if the lookup fails.
///
/// # Errors
///
/// Returns an error if `ip` is not a valid IP address.
pub async fn reverse_dns_lookup(
    ip: &str,
    resolver: &TokioResolver,
) -> Result<Option<String>, Error> {
    use hickory_resolver::proto::rr::Name;
    let addr: IpAddr = ip.parse()?;
    match resolver.reverse_lookup(Name::from(addr)).await {
        Ok(response) => {
            use hickory_resolver::proto::rr::RData;
            let name = response.answers().iter().find_map(|record| {
                if let RData::PTR(ptr) = &record.data {
                    Some(ptr.to_utf8())
                } else {
                    None
                }
            });
            Ok(name)
        }
        Err(e) => {
            log::warn!("Failed to perform reverse DNS lookup for {ip}: {e}");
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn prefer_public_ip_skips_rfc1918_when_public_present() {
        let private = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let public = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(
            prefer_public_ip([private, public]),
            Some(public),
            "analytics IP must match SafeResolver public preference"
        );
    }

    #[test]
    fn prefer_public_ip_keeps_first_when_all_private() {
        let first = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let second = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(prefer_public_ip([first, second]), Some(first));
    }

    #[test]
    fn prefer_public_ip_empty_is_none() {
        assert_eq!(prefer_public_ip(std::iter::empty()), None);
    }

    #[test]
    fn prefer_public_ip_public_ipv6_beats_ula() {
        let ula = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        let public = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));
        assert_eq!(prefer_public_ip([ula, public]), Some(public));
    }

    #[tokio::test]
    #[ignore = "live DNS; run with --ignored"]
    async fn test_resolve_host_to_ip_success() {
        let resolver = crate::initialization::test_resolver();
        let ip = resolve_host_to_ip("example.com", &resolver)
            .await
            .expect("example.com should resolve when network DNS is available");
        assert!(ip.parse::<IpAddr>().is_ok(), "expected an IP, got {ip}");
    }

    #[tokio::test]
    #[ignore = "live reverse DNS; run with --ignored"]
    async fn test_reverse_dns_lookup_success() {
        let resolver = crate::initialization::test_resolver();
        let result = reverse_dns_lookup("8.8.8.8", &resolver)
            .await
            .expect("PTR lookup should complete when network DNS is available");
        if let Some(hostname) = result {
            assert!(
                !hostname.is_empty(),
                "PTR hostname should not be empty when present"
            );
        }
    }

    #[tokio::test]
    async fn test_reverse_dns_lookup_invalid_ip() {
        let resolver = crate::initialization::test_resolver();
        let result = reverse_dns_lookup("not.an.ip.address", &resolver).await;
        assert!(
            result.is_err(),
            "Reverse DNS lookup should error on invalid IP"
        );
    }
}
