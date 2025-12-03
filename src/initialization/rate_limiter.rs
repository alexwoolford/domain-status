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
                        let permits_to_add_f64 = current_rps_value as f64 * elapsed.as_secs_f64() + fractional_permits;
                        let permits_to_add = permits_to_add_f64 as u32;
                        fractional_permits = permits_to_add_f64 - permits_to_add as f64;

                        if permits_to_add > 0 {
                            permits.add_permits(permits_to_add as usize);
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
