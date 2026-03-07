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
///
/// Instances are usually created via [`init_rate_limiter()`].
pub struct RateLimiter {
    permits: Arc<TokioSemaphore>,
    #[allow(dead_code)]
    capacity: usize,
    current_rps: Arc<std::sync::atomic::AtomicU32>,
    #[allow(dead_code)] // Used for cancellation token reference
    shutdown: tokio_util::sync::CancellationToken,
}

fn compute_refill_permits(
    current_rps: u32,
    elapsed: std::time::Duration,
    available: usize,
    capacity: usize,
    fractional_permits: f64,
) -> (usize, f64) {
    if current_rps == 0 || available >= capacity {
        return (0, 0.0);
    }

    #[allow(clippy::cast_precision_loss)]
    let permits_to_add_f64 = current_rps as f64 * elapsed.as_secs_f64() + fractional_permits;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let whole_permits = permits_to_add_f64.floor() as usize;
    let permits_to_restore = capacity.saturating_sub(available);
    let permits_to_add = whole_permits.min(permits_to_restore);

    let new_fractional = if permits_to_add == permits_to_restore {
        0.0
    } else {
        #[allow(clippy::cast_precision_loss)]
        {
            permits_to_add_f64 - whole_permits as f64
        }
    };

    (permits_to_add, new_fractional)
}

impl RateLimiter {
    /// Acquires a permit from the rate limiter, blocking until one is available.
    ///
    /// If the semaphore is closed (e.g., during shutdown), the acquire is skipped
    /// and a warning is logged. This prevents requests from flooding the target
    /// during shutdown race conditions.
    pub async fn acquire(&self) {
        match self.permits.acquire().await {
            Ok(permit) => {
                // Consume the token permanently; replenishment happens in the background ticker.
                permit.forget();
            }
            Err(_) => {
                log::warn!("Rate limiter semaphore closed, skipping throttle");
            }
        }
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
///
/// # Examples
///
/// Disabled mode:
///
/// ```
/// use domain_status::initialization::init_rate_limiter;
///
/// assert!(init_rate_limiter(0, 10).is_none());
/// ```
///
/// Basic lifecycle with explicit shutdown:
///
/// ```no_run
/// use domain_status::initialization::init_rate_limiter;
///
/// # #[tokio::main]
/// # async fn main() {
/// let (limiter, shutdown) = init_rate_limiter(10, 20).expect("rate limiter enabled");
/// limiter.acquire().await;
///
/// // During teardown, stop the background refill task.
/// shutdown.cancel();
/// # }
/// ```
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
                        let available = permits.available_permits();
                        let (permits_to_add, new_fractional_permits) = compute_refill_permits(
                            current_rps_value,
                            elapsed,
                            available,
                            capacity,
                            fractional_permits,
                        );
                        fractional_permits = new_fractional_permits;

                        if permits_to_add > 0 {
                            permits.add_permits(permits_to_add);
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
    use std::sync::Arc;
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

    #[tokio::test(start_paused = true)]
    async fn test_rate_limiter_acquire_consumes_burst_capacity() {
        let (limiter, _shutdown) = init_rate_limiter(1, 2).unwrap();

        limiter.acquire().await;
        limiter.acquire().await;

        let blocked = timeout(Duration::from_millis(1), limiter.acquire()).await;
        assert!(blocked.is_err(), "third acquire should block until refill");
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

    #[tokio::test(start_paused = true)]
    async fn test_rate_limiter_token_replenishment_unblocks_waiter() {
        let (limiter, _shutdown) = init_rate_limiter(10, 1).unwrap();

        limiter.acquire().await;

        let acquire = tokio::spawn({
            let limiter = Arc::clone(&limiter);
            async move { limiter.acquire().await }
        });

        tokio::time::advance(Duration::from_millis(90)).await;
        assert!(
            !acquire.is_finished(),
            "waiter should still be blocked before refill"
        );

        tokio::time::advance(Duration::from_millis(20)).await;
        acquire.await.expect("waiter task should complete");
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

    #[tokio::test(start_paused = true)]
    async fn test_rate_limiter_burst_capacity_is_capped() {
        let (permits_to_add, fractional) =
            compute_refill_permits(1, Duration::from_secs(5), 2, 3, 0.0);
        assert_eq!(
            permits_to_add, 1,
            "bucket should only refill the missing slot"
        );
        assert!(
            fractional.abs() < f64::EPSILON,
            "overflow beyond burst capacity should be discarded"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_rate_limiter_dynamic_rps_update_changes_refill_speed() {
        let (limiter, _shutdown) = init_rate_limiter(1, 1).unwrap();

        limiter.acquire().await;
        let blocked = timeout(Duration::from_millis(1), limiter.acquire()).await;
        assert!(blocked.is_err(), "single-token burst should be exhausted");

        limiter.update_rps(10);

        tokio::time::advance(Duration::from_millis(110)).await;
        timeout(Duration::from_millis(10), limiter.acquire())
            .await
            .expect("updated RPS should replenish promptly");
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

    #[test]
    fn test_compute_refill_permits_accumulates_fractional_tokens() {
        let (permits_to_add, fractional) =
            compute_refill_permits(3, Duration::from_millis(100), 0, 5, 0.0);
        assert_eq!(permits_to_add, 0);
        assert!(fractional > 0.29 && fractional < 0.31);

        let (permits_to_add, fractional) =
            compute_refill_permits(3, Duration::from_millis(300), 0, 5, fractional);
        assert_eq!(permits_to_add, 1);
        assert!(fractional > 0.19 && fractional < 0.21);
    }
}
