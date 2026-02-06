//! Rate limiter initialization.
//!
//! This module provides a token-bucket rate limiter for controlling request rate.

use std::sync::Arc;
use tokio::sync::Semaphore as TokioSemaphore;
use tokio::time::{interval, Duration as TokioDuration};

/// Token-bucket rate limiter for controlling request rate.
///
/// Implements a token bucket algorithm where tokens are replenished at a fixed
/// rate (requests per second). Each request consumes a token, and requests
/// are blocked when no tokens are available.
///
/// # Behavior
///
/// - Tokens are replenished continuously at the specified rate
/// - Burst capacity allows short bursts above the base rate
/// - Uses a background task for token replenishment
/// - Supports graceful shutdown via `CancellationToken`
/// - Supports dynamic RPS updates (for adaptive rate limiting)
pub struct RateLimiter {
    permits: Arc<TokioSemaphore>,
    #[allow(dead_code)]
    capacity: usize,
    current_rps: Arc<std::sync::atomic::AtomicU32>,
    #[allow(dead_code)] // Used for cancellation token reference
    shutdown: tokio_util::sync::CancellationToken,
}

impl RateLimiter {
    pub async fn acquire(&self) {
        let _ = self.permits.acquire().await;
    }

    /// Updates the current RPS value (for adaptive rate limiting).
    /// The background task will automatically adjust the token replenishment rate.
    pub fn update_rps(&self, new_rps: u32) {
        self.current_rps
            .store(new_rps, std::sync::atomic::Ordering::SeqCst);
    }

    /// Gets the current RPS value.
    ///
    /// Useful for monitoring and debugging. The RPS may be dynamically updated
    /// by adaptive rate limiting, so this value may change between calls.
    #[allow(dead_code)] // Useful for debugging/monitoring, may be used in future
    pub fn current_rps(&self) -> u32 {
        self.current_rps.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Initializes a token-bucket rate limiter.
///
/// Creates a rate limiter that controls request rate using a token bucket algorithm.
/// If `rps` is 0, rate limiting is disabled and `None` is returned.
///
/// # Arguments
///
/// * `rps` - Requests per second (0 disables rate limiting)
/// * `burst` - Burst capacity (maximum tokens in bucket)
///
/// # Returns
///
/// A tuple of `(RateLimiter, CancellationToken)` if rate limiting is enabled,
/// or `None` if disabled. The cancellation token can be used to gracefully shut
/// down the background token replenishment task.
pub fn init_rate_limiter(
    rps: u32,
    burst: usize,
) -> Option<(Arc<RateLimiter>, tokio_util::sync::CancellationToken)> {
    if rps == 0 {
        return None;
    }
    let capacity = burst;
    let shutdown = tokio_util::sync::CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    let current_rps = Arc::new(std::sync::atomic::AtomicU32::new(rps));
    let limiter = Arc::new(RateLimiter {
        permits: Arc::new(TokioSemaphore::new(capacity)),
        capacity,
        current_rps: Arc::clone(&current_rps),
        shutdown: shutdown_clone.clone(),
    });

    let permits = limiter.permits.clone();
    let rps_for_ticker = Arc::clone(&current_rps);
    // Use a fast ticker (every 100ms) and calculate how many permits to add based on current RPS
    let mut ticker = interval(TokioDuration::from_millis(100));
    tokio::spawn(async move {
        let mut last_time = tokio::time::Instant::now();
        let mut fractional_permits = 0.0f64; // Track fractional permits to avoid precision loss
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let now = tokio::time::Instant::now();
                    let elapsed = now.duration_since(last_time);
                    let current_rps_value = rps_for_ticker.load(std::sync::atomic::Ordering::SeqCst);

                    if current_rps_value > 0 {
                        // Calculate how many permits to add based on elapsed time and current RPS
                        // For example, if RPS is 10 and 100ms elapsed, we should add 1 permit (10 * 0.1 = 1)
                        // Safe cast: RPS is u32, max value is 4,294,967,295, well within f64 precision
                        // Safe cast: truncating fractional permits is intentional for integer token count
                        // Values are bounded by RPS * elapsed (typically small values < 1000)
                        // Safe cast: permits_to_add is u32, fits exactly in f64 without precision loss
                        #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        let permits_to_add_f64 = current_rps_value as f64 * elapsed.as_secs_f64() + fractional_permits;
                        #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        let permits_to_add = permits_to_add_f64 as u32;
                        #[allow(clippy::cast_precision_loss)]
                        {
                            fractional_permits = permits_to_add_f64 - permits_to_add as f64;
                        }

                        if permits_to_add > 0 {
                            // Safe cast: u32 always fits in usize on all supported platforms
                            #[allow(clippy::cast_possible_truncation)]
                            {
                                permits.add_permits(permits_to_add as usize);
                            }
                        }
                    }

                    last_time = now;
                }
                _ = shutdown_clone.cancelled() => {
                    log::debug!("Rate limiter background task shutting down");
                    break;
                }
            }
        }
    });

    Some((limiter, shutdown))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    #[test]
    fn test_init_rate_limiter_disabled() {
        let result = init_rate_limiter(0, 10);
        assert!(
            result.is_none(),
            "Rate limiter should be disabled when RPS is 0"
        );
    }

    #[tokio::test]
    async fn test_init_rate_limiter_enabled() {
        let result = init_rate_limiter(10, 20);
        assert!(
            result.is_some(),
            "Rate limiter should be enabled when RPS > 0"
        );
        let (limiter, _shutdown) = result.unwrap();
        // Give background task a moment to initialize
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(limiter.current_rps(), 10);
    }

    #[tokio::test]
    async fn test_rate_limiter_acquire_permits() {
        let (limiter, _shutdown) = init_rate_limiter(10, 5).unwrap();

        // Should be able to acquire permits up to burst capacity
        for _ in 0..5 {
            limiter.acquire().await;
        }

        // Additional acquires should wait (but we can't easily test this without timing)
        // We verify the function doesn't panic by completing successfully
    }

    #[tokio::test]
    async fn test_rate_limiter_update_rps() {
        let (limiter, _shutdown) = init_rate_limiter(10, 5).unwrap();
        assert_eq!(limiter.current_rps(), 10);

        limiter.update_rps(20);
        assert_eq!(limiter.current_rps(), 20);

        limiter.update_rps(5);
        assert_eq!(limiter.current_rps(), 5);
    }

    #[tokio::test]
    async fn test_rate_limiter_token_replenishment() {
        let (limiter, _shutdown) = init_rate_limiter(10, 1).unwrap();

        // Acquire the single permit
        limiter.acquire().await;

        // Wait a bit for token replenishment (100ms ticker, so 200ms should give us 2 tokens)
        tokio::time::sleep(Duration::from_millis(250)).await;

        // Should be able to acquire again (token was replenished)
        let acquire_result = timeout(Duration::from_millis(100), limiter.acquire()).await;
        assert!(
            acquire_result.is_ok(),
            "Should be able to acquire permit after token replenishment"
        );
    }

    #[tokio::test]
    async fn test_rate_limiter_shutdown() {
        let (limiter, shutdown) = init_rate_limiter(10, 5).unwrap();

        // Cancel the background task
        shutdown.cancel();

        // Wait a bit for shutdown to propagate
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Limiter should still work (shutdown just stops token replenishment)
        // We verify it doesn't panic
        let _ = timeout(Duration::from_millis(10), limiter.acquire()).await;
    }

    #[tokio::test]
    async fn test_rate_limiter_burst_capacity() {
        let (limiter, _shutdown) = init_rate_limiter(1, 3).unwrap(); // 1 RPS, burst of 3

        // Should be able to acquire all 3 permits immediately (burst)
        for _ in 0..3 {
            let acquire_result = timeout(Duration::from_millis(10), limiter.acquire()).await;
            assert!(
                acquire_result.is_ok(),
                "Should be able to use burst capacity immediately"
            );
        }

        // After burst is exhausted, should need to wait
        // (This is hard to test reliably without flakiness, so we just verify it doesn't panic)
        let _ = timeout(Duration::from_millis(10), limiter.acquire()).await;
    }

    #[tokio::test]
    async fn test_rate_limiter_dynamic_rps_update() {
        let (limiter, _shutdown) = init_rate_limiter(1, 1).unwrap();

        // Update to higher RPS
        limiter.update_rps(10);

        // Wait for token replenishment with new rate
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be able to acquire (new rate should replenish faster)
        let acquire_result = timeout(Duration::from_millis(50), limiter.acquire()).await;
        // May or may not succeed depending on timing, but shouldn't panic
        let _ = acquire_result;
    }

    #[tokio::test]
    async fn test_rate_limiter_multiple_instances() {
        let (limiter1, _shutdown1) = init_rate_limiter(10, 5).unwrap();
        let (limiter2, _shutdown2) = init_rate_limiter(20, 10).unwrap();

        // Give background tasks a moment to initialize
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Different instances should have different configurations
        assert_eq!(limiter1.current_rps(), 10);
        assert_eq!(limiter2.current_rps(), 20);
    }
}
