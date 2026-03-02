//! Per-domain concurrency limiter.
//!
//! Limits the number of concurrent requests to any single registered domain.
//! This prevents overwhelming a single server even when global concurrency is high.
//!
//! Uses `moka` (already a dependency) as a concurrent cache with TTL-based eviction
//! so that stale domain entries are automatically cleaned up.

use std::sync::Arc;
use std::time::Duration;

use moka::sync::Cache;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Per-domain concurrency limiter.
///
/// Each registered domain gets its own semaphore with `max_per_domain` permits.
/// When all permits for a domain are held, additional requests to that domain
/// will block until a permit is released.
///
/// Domain keys are normalized using the Public Suffix List so that
/// `www.example.com` and `api.example.com` share the same limit.
pub struct PerDomainLimiter {
    limiters: Cache<String, Arc<Semaphore>>,
    max_per_domain: usize,
}

impl PerDomainLimiter {
    /// Creates a new per-domain limiter.
    ///
    /// # Arguments
    ///
    /// * `max_per_domain` - Maximum concurrent requests per registered domain
    pub fn new(max_per_domain: usize) -> Self {
        Self {
            limiters: Cache::builder()
                .time_to_idle(Duration::from_secs(300)) // evict after 5 min idle
                .max_capacity(100_000)
                .build(),
            max_per_domain,
        }
    }

    /// Acquires a per-domain permit.
    ///
    /// Blocks until a permit is available for the given domain.
    /// The returned `OwnedSemaphorePermit` must be held until the request completes.
    ///
    /// # Arguments
    ///
    /// * `domain` - The registered domain key (e.g., "example.com")
    pub async fn acquire(
        &self,
        domain: &str,
    ) -> Result<OwnedSemaphorePermit, tokio::sync::AcquireError> {
        let max = self.max_per_domain;
        let semaphore = self
            .limiters
            .get_with(domain.to_string(), || Arc::new(Semaphore::new(max)));
        semaphore.acquire_owned().await
    }

    /// Returns the number of domains currently being tracked.
    #[allow(dead_code)] // Available for monitoring/debugging
    pub fn tracked_domains(&self) -> u64 {
        self.limiters.entry_count()
    }
}

/// Extract the registered domain from a URL string.
///
/// Uses the Public Suffix List to normalize subdomains:
/// - `www.example.com` -> `example.com`
/// - `api.example.com` -> `example.com`
///
/// Falls back to the raw hostname for IPs or domains the PSL can't parse.
pub fn extract_domain_key(url_str: &str) -> String {
    url::Url::parse(url_str)
        .ok()
        .and_then(|u| {
            u.host_str().map(|host| {
                // If host is an IP address, use it directly
                if host.parse::<std::net::IpAddr>().is_ok() {
                    return host.to_string();
                }
                // Try PSL lookup for domain names
                psl::domain_str(host)
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| host.to_string())
            })
        })
        .unwrap_or_else(|| url_str.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain_key_subdomain() {
        assert_eq!(
            extract_domain_key("https://www.example.com/path"),
            "example.com"
        );
    }

    #[test]
    fn test_extract_domain_key_api_subdomain() {
        assert_eq!(extract_domain_key("https://api.example.com"), "example.com");
    }

    #[test]
    fn test_extract_domain_key_bare_domain() {
        assert_eq!(extract_domain_key("https://example.com"), "example.com");
    }

    #[test]
    fn test_extract_domain_key_ip_address() {
        assert_eq!(
            extract_domain_key("https://192.168.1.1/test"),
            "192.168.1.1"
        );
    }

    #[test]
    fn test_extract_domain_key_invalid_url() {
        assert_eq!(extract_domain_key("not-a-url"), "not-a-url");
    }

    #[tokio::test]
    async fn test_per_domain_limiter_exact_capacity() {
        // Acquire exactly max_per_domain permits — all should succeed immediately.
        // The (max_per_domain + 1)th should block.
        let limiter = Arc::new(PerDomainLimiter::new(3));

        let p1 = tokio::time::timeout(Duration::from_millis(50), limiter.acquire("example.com"))
            .await
            .expect("1st permit should not block")
            .expect("1st permit should succeed");
        let p2 = tokio::time::timeout(Duration::from_millis(50), limiter.acquire("example.com"))
            .await
            .expect("2nd permit should not block")
            .expect("2nd permit should succeed");
        let p3 = tokio::time::timeout(Duration::from_millis(50), limiter.acquire("example.com"))
            .await
            .expect("3rd permit should not block")
            .expect("3rd permit should succeed");

        // 4th should block (capacity exhausted)
        let limiter_clone = Arc::clone(&limiter);
        let fourth = tokio::time::timeout(
            Duration::from_millis(50),
            limiter_clone.acquire("example.com"),
        )
        .await;
        assert!(fourth.is_err(), "4th permit should timeout (capacity = 3)");

        // Release one, then 4th should succeed
        drop(p1);
        let _p4 = tokio::time::timeout(Duration::from_millis(50), limiter.acquire("example.com"))
            .await
            .expect("4th permit should succeed after release")
            .expect("acquire should not error");

        // Keep permits alive so they're not dropped before assertions
        drop(p2);
        drop(p3);
    }

    #[tokio::test]
    async fn test_per_domain_limiter_blocks_when_full() {
        let limiter = Arc::new(PerDomainLimiter::new(1));
        let permit = limiter.acquire("example.com").await.unwrap();

        let limiter_clone = Arc::clone(&limiter);
        let handle = tokio::spawn(async move {
            // This should block until the first permit is dropped
            tokio::time::timeout(
                Duration::from_millis(50),
                limiter_clone.acquire("example.com"),
            )
            .await
        });

        // Should timeout since the permit is still held
        let result = handle.await.unwrap();
        assert!(result.is_err(), "Should have timed out");

        // Now drop the permit and try again
        drop(permit);

        let _permit2 =
            tokio::time::timeout(Duration::from_millis(50), limiter.acquire("example.com"))
                .await
                .expect("Should not timeout after permit dropped")
                .expect("Should acquire permit");
    }

    #[tokio::test]
    async fn test_per_domain_limiter_does_not_block_different_domain() {
        // Verify that domain A being full does NOT block domain B
        let limiter = Arc::new(PerDomainLimiter::new(1));
        let _permit_a = limiter.acquire("a.com").await.unwrap();

        // b.com should acquire immediately even though a.com is full
        let result =
            tokio::time::timeout(Duration::from_millis(50), limiter.acquire("b.com")).await;
        assert!(result.is_ok(), "Different domain should not be blocked");
    }

    #[tokio::test]
    async fn test_subdomains_share_limit() {
        // www.example.com and api.example.com should both resolve to "example.com"
        let key1 = extract_domain_key("https://www.example.com/page");
        let key2 = extract_domain_key("https://api.example.com/v1");
        assert_eq!(key1, key2, "Subdomains should share the same domain key");

        // Verify they actually share the same semaphore
        let limiter = Arc::new(PerDomainLimiter::new(1));
        let _permit = limiter.acquire(&key1).await.unwrap();

        // Second subdomain should block
        let limiter_clone = Arc::clone(&limiter);
        let key2_owned = key2.clone();
        let result = tokio::time::timeout(
            Duration::from_millis(50),
            limiter_clone.acquire(&key2_owned),
        )
        .await;
        assert!(
            result.is_err(),
            "api.example.com should be blocked because www.example.com holds the permit"
        );
    }

    #[test]
    fn test_extract_domain_key_co_uk() {
        // Multi-part TLDs should be handled correctly
        assert_eq!(
            extract_domain_key("https://www.example.co.uk/page"),
            "example.co.uk"
        );
    }

    #[test]
    fn test_extract_domain_key_localhost() {
        assert_eq!(extract_domain_key("http://localhost:8080/api"), "localhost");
    }

    #[test]
    fn test_extract_domain_key_ipv6() {
        // url::Url preserves brackets around IPv6 addresses
        assert_eq!(extract_domain_key("https://[::1]:443/"), "[::1]");
    }
}
