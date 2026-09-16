//! Per-host URL-admission limiter (token bucket, lazy refill).
//!
//! Complements the global [`super::RateLimiter`]: after a global token is taken,
//! each host is capped independently so a long list on one origin cannot consume
//! the whole worker pool at the global RPS.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Semaphore;
use tokio::time::{Duration, Instant};

use super::rate_limiter::compute_refill_permits;

/// Default per-host URL-admission rate when global `--rate-limit-rps` is enabled.
pub const PER_HOST_RATE_LIMIT_RPS: u32 = 2;
/// Burst capacity matching one second of [`PER_HOST_RATE_LIMIT_RPS`].
pub const PER_HOST_RATE_LIMIT_BURST: usize = 2;

/// Per-host token buckets keyed by lowercase URL host.
#[derive(Debug)]
pub struct HostRateLimiter {
    rps: u32,
    burst: usize,
    buckets: Mutex<HashMap<String, Arc<HostBucket>>>,
}

#[derive(Debug)]
struct HostBucket {
    permits: Semaphore,
    capacity: usize,
    rps: u32,
    last_refill: Mutex<Instant>,
    fractional: Mutex<f64>,
    logged_wait: AtomicBool,
}

impl HostRateLimiter {
    /// Creates a limiter. `rps == 0` is not used; callers pass `None` instead.
    #[must_use]
    pub fn new(rps: u32, burst: usize) -> Self {
        Self {
            rps,
            burst: burst.max(1),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Lowercase host for rate-limit grouping, or `None` when the URL has no host.
    #[must_use]
    pub fn host_key(url: &str) -> Option<String> {
        parse_url_for_host(url).and_then(|parsed| parsed.host_str().map(str::to_ascii_lowercase))
    }

    /// Acquires one per-host token for `url`. No-ops when the URL has no host.
    pub async fn acquire(&self, url: &str) {
        let Some(host) = Self::host_key(url) else {
            return;
        };
        let bucket = self.bucket(&host);
        bucket.acquire(&host).await;
    }

    fn bucket(&self, host: &str) -> Arc<HostBucket> {
        let mut map = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        map.entry(host.to_string())
            .or_insert_with(|| {
                Arc::new(HostBucket {
                    permits: Semaphore::new(self.burst),
                    capacity: self.burst,
                    rps: self.rps,
                    last_refill: Mutex::new(Instant::now()),
                    fractional: Mutex::new(0.0),
                    logged_wait: AtomicBool::new(false),
                })
            })
            .clone()
    }
}

impl HostBucket {
    fn refill(&self) {
        let now = Instant::now();
        let mut last = self
            .last_refill
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let elapsed = now.saturating_duration_since(*last);
        let available = self.permits.available_permits();
        let mut fractional = self
            .fractional
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (permits_to_add, new_fractional) =
            compute_refill_permits(self.rps, elapsed, available, self.capacity, *fractional);
        *fractional = new_fractional;
        if permits_to_add > 0 {
            self.permits.add_permits(permits_to_add);
        }
        *last = now;
    }

    async fn acquire(&self, host: &str) {
        loop {
            self.refill();
            match self.permits.try_acquire() {
                Ok(permit) => {
                    permit.forget();
                    return;
                }
                Err(_) => {
                    if !self.logged_wait.swap(true, Ordering::Relaxed) {
                        log::debug!("throttling {host} ({} rps per host)", self.rps);
                    }
                    tokio::time::sleep(per_host_retry_delay(self.rps)).await;
                }
            }
        }
    }
}

fn parse_url_for_host(url: &str) -> Option<url::Url> {
    url::Url::parse(url)
        .ok()
        .or_else(|| url::Url::parse(&format!("https://{url}")).ok())
}

fn per_host_retry_delay(rps: u32) -> Duration {
    if rps == 0 {
        Duration::from_millis(100)
    } else {
        Duration::from_millis(1000 / u64::from(rps.max(1)))
    }
}

/// Builds the default per-host limiter, or `None` when global rate limiting is off.
#[must_use]
pub fn init_host_rate_limiter(global_rps: u32) -> Option<Arc<HostRateLimiter>> {
    if global_rps == 0 {
        None
    } else {
        Some(Arc::new(HostRateLimiter::new(
            PER_HOST_RATE_LIMIT_RPS,
            PER_HOST_RATE_LIMIT_BURST,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration as StdDuration;
    use tokio::time::timeout;

    #[test]
    fn host_key_lowercases_and_ignores_path() {
        assert_eq!(
            HostRateLimiter::host_key("https://Example.COM/a"),
            Some("example.com".to_string())
        );
        assert_eq!(
            HostRateLimiter::host_key("https://example.com/b?x=1"),
            Some("example.com".to_string())
        );
        assert_eq!(
            HostRateLimiter::host_key("example.org/path"),
            Some("example.org".to_string())
        );
    }

    #[test]
    fn host_key_missing_for_empty() {
        assert_eq!(HostRateLimiter::host_key(""), None);
    }

    #[test]
    fn init_host_rate_limiter_disabled_when_global_rps_zero() {
        assert!(init_host_rate_limiter(0).is_none());
        assert!(init_host_rate_limiter(15).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn same_host_third_acquire_waits_for_refill() {
        let limiter = HostRateLimiter::new(2, 2);
        limiter.acquire("https://example.com/a").await;
        limiter.acquire("https://example.com/b").await;

        let blocked = timeout(
            StdDuration::from_millis(1),
            limiter.acquire("https://example.com/c"),
        )
        .await;
        assert!(
            blocked.is_err(),
            "third same-host acquire should wait after burst is spent"
        );

        let waiter = tokio::spawn({
            let limiter = Arc::new(limiter);
            async move {
                limiter.acquire("https://example.com/c").await;
            }
        });
        tokio::time::advance(StdDuration::from_millis(400)).await;
        assert!(
            !waiter.is_finished(),
            "2 rps should still block before ~500ms"
        );
        tokio::time::advance(StdDuration::from_millis(200)).await;
        waiter.await.expect("waiter should complete after refill");
    }

    #[tokio::test(start_paused = true)]
    async fn two_hosts_do_not_share_a_bucket() {
        let limiter = HostRateLimiter::new(2, 2);
        limiter.acquire("https://a.example/1").await;
        limiter.acquire("https://a.example/2").await;

        timeout(
            StdDuration::from_millis(1),
            limiter.acquire("https://b.example/1"),
        )
        .await
        .expect("other host should still have burst tokens");
    }
}
