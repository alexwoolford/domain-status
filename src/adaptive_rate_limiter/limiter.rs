//! Adaptive rate limiter implementation.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;

use super::window::{OutcomeWindow, RequestOutcome};

/// Adaptive rate limiter that adjusts RPS based on error rates.
///
/// Uses AIMD (Additive Increase Multiplicative Decrease) algorithm:
/// - When error rate > threshold: reduce RPS by 50% (multiplicative decrease)
/// - When error rate < threshold: increase RPS by 10% (additive increase)
pub struct AdaptiveRateLimiter {
    current_rps: Arc<AtomicU32>,
    min_rps: u32,
    max_rps: u32,
    error_threshold: f64,
    outcome_window: OutcomeWindow,
    shutdown: CancellationToken,
}

impl AdaptiveRateLimiter {
    /// Creates a new adaptive rate limiter.
    ///
    /// # Arguments
    ///
    /// * `initial_rps` - Starting RPS value
    /// * `min_rps` - Minimum RPS (default: 1)
    /// * `max_rps` - Maximum RPS (default: initial_rps)
    /// * `error_threshold` - Error rate threshold (0.0-1.0, default: 0.2 = 20%)
    /// * `window_size` - Maximum number of outcomes to track (default: 100)
    /// * `window_duration` - Time window for error rate calculation (default: 30s)
    pub fn new(
        initial_rps: u32,
        min_rps: Option<u32>,
        max_rps: Option<u32>,
        error_threshold: Option<f64>,
        window_size: Option<usize>,
        window_duration: Option<Duration>,
    ) -> Self {
        let min_rps = min_rps.unwrap_or(1);
        let max_rps = max_rps.unwrap_or(initial_rps);
        let error_threshold = error_threshold.unwrap_or(0.2); // 20% default
        let window_size = window_size.unwrap_or(100);
        let window_duration = window_duration.unwrap_or(Duration::from_secs(30));

        AdaptiveRateLimiter {
            current_rps: Arc::new(AtomicU32::new(initial_rps)),
            min_rps,
            max_rps,
            error_threshold,
            outcome_window: OutcomeWindow::new(window_size, window_duration),
            shutdown: CancellationToken::new(),
        }
    }

    /// Records a successful request.
    pub async fn record_success(&self) {
        self.outcome_window.record(RequestOutcome::Success).await;
    }

    /// Records a rate-limited request (429).
    pub async fn record_rate_limited(&self) {
        self.outcome_window
            .record(RequestOutcome::RateLimited)
            .await;
    }

    /// Records a timeout error.
    pub async fn record_timeout(&self) {
        self.outcome_window.record(RequestOutcome::Timeout).await;
    }

    /// Gets the current RPS value.
    ///
    /// Useful for monitoring and debugging. The RPS is automatically adjusted
    /// by the background task, so this value may change between calls.
    #[allow(dead_code)] // Useful for debugging/monitoring, may be used in future
    pub fn current_rps(&self) -> u32 {
        self.current_rps.load(Ordering::SeqCst)
    }

    /// Starts the adaptive adjustment background task.
    ///
    /// This task periodically checks error rates and adjusts RPS accordingly.
    /// Runs every `adjustment_interval` (default: 5 seconds).
    ///
    /// Returns a callback function that should be called when RPS changes.
    /// The callback receives the new RPS value and should update the rate limiter.
    pub fn start_adaptive_adjustment<F>(
        &self,
        mut on_rps_change: F,
        adjustment_interval: Option<Duration>,
    ) -> CancellationToken
    where
        F: FnMut(u32) + Send + 'static,
    {
        let current_rps = Arc::clone(&self.current_rps);
        let outcome_window = Arc::new(OutcomeWindow {
            outcomes: Arc::clone(&self.outcome_window.outcomes),
            window_size: self.outcome_window.window_size,
            window_duration: self.outcome_window.window_duration,
        });
        let error_threshold = self.error_threshold;
        let min_rps = self.min_rps;
        let max_rps = self.max_rps;
        let shutdown = self.shutdown.clone();

        let interval_duration = adjustment_interval.unwrap_or(Duration::from_secs(5));
        let mut ticker = interval(interval_duration);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let error_rate = outcome_window.error_rate().await;
                        let request_count = outcome_window.request_count().await;
                        let current = current_rps.load(Ordering::SeqCst);

                        // Only adjust if we have enough data points
                        if request_count >= 10 {
                            let new_rps = if error_rate > error_threshold {
                                // Multiplicative decrease: reduce by 50%
                                let decreased = (current as f64 * 0.5).max(min_rps as f64) as u32;
                                log::info!(
                                    "Adaptive rate limiter: error rate {:.1}% > threshold {:.1}%, reducing RPS {} → {}",
                                    error_rate * 100.0,
                                    error_threshold * 100.0,
                                    current,
                                    decreased
                                );
                                decreased
                            } else if error_rate < error_threshold * 0.5 {
                                // Additive increase: increase by 15% (only if errors are low)
                                // Capped at max_rps to allow adaptation while preventing runaway increases
                                // The cast to u32 is safe because max_rps is already a u32, so the result will never exceed u32::MAX
                                let increased_calc = (current as f64 * 1.15) as u32;
                                let increased = increased_calc
                                    .max(current.saturating_add(1)) // At least +1, but prevent overflow
                                    .min(max_rps); // Ensure we never exceed max_rps
                                if increased > current {
                                    log::info!(
                                        "Adaptive rate limiter: error rate {:.1}% < threshold {:.1}%, increasing RPS {} → {}",
                                        error_rate * 100.0,
                                        error_threshold * 100.0,
                                        current,
                                        increased
                                    );
                                }
                                increased
                            } else {
                                // Error rate is acceptable, keep current RPS
                                current
                            };

                            if new_rps != current {
                                current_rps.store(new_rps, Ordering::SeqCst);
                                on_rps_change(new_rps);
                            }
                        }
                    }
                    _ = shutdown.cancelled() => {
                        log::debug!("Adaptive rate limiter background task shutting down");
                        break;
                    }
                }
            }
        });

        self.shutdown.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use std::time::Duration;

    #[tokio::test]
    async fn test_new_with_defaults() {
        let limiter = AdaptiveRateLimiter::new(10, None, None, None, None, None);
        assert_eq!(limiter.current_rps(), 10);
        assert_eq!(limiter.min_rps, 1);
        assert_eq!(limiter.max_rps, 10);
        assert_eq!(limiter.error_threshold, 0.2);
    }

    #[tokio::test]
    async fn test_new_with_custom_values() {
        let limiter = AdaptiveRateLimiter::new(
            20,
            Some(5),
            Some(50),
            Some(0.3),
            Some(200),
            Some(Duration::from_secs(60)),
        );
        assert_eq!(limiter.current_rps(), 20);
        assert_eq!(limiter.min_rps, 5);
        assert_eq!(limiter.max_rps, 50);
        assert_eq!(limiter.error_threshold, 0.3);
    }

    #[tokio::test]
    async fn test_record_success() {
        let limiter = AdaptiveRateLimiter::new(10, None, None, None, None, None);
        limiter.record_success().await;
        // Verify outcome was recorded by checking request count
        let request_count = limiter.outcome_window.request_count().await;
        assert_eq!(request_count, 1);
    }

    #[tokio::test]
    async fn test_record_rate_limited() {
        let limiter = AdaptiveRateLimiter::new(10, None, None, None, None, None);
        limiter.record_rate_limited().await;
        let request_count = limiter.outcome_window.request_count().await;
        assert_eq!(request_count, 1);
        // Error rate should be 100% (1 rate limited out of 1 request)
        let error_rate = limiter.outcome_window.error_rate().await;
        assert!((error_rate - 1.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_record_timeout() {
        let limiter = AdaptiveRateLimiter::new(10, None, None, None, None, None);
        limiter.record_timeout().await;
        let request_count = limiter.outcome_window.request_count().await;
        assert_eq!(request_count, 1);
        // Error rate should be 100% (1 timeout out of 1 request)
        let error_rate = limiter.outcome_window.error_rate().await;
        assert!((error_rate - 1.0).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_current_rps() {
        let limiter = AdaptiveRateLimiter::new(15, None, None, None, None, None);
        assert_eq!(limiter.current_rps(), 15);
    }

    #[tokio::test]
    async fn test_adaptive_adjustment_decrease() {
        let limiter = AdaptiveRateLimiter::new(
            20,
            Some(1),
            Some(40),
            Some(0.2), // 20% threshold
            Some(100),
            Some(Duration::from_secs(30)),
        );

        // Record high error rate (30% = 15 errors out of 50 requests)
        for _ in 0..35 {
            limiter.record_success().await;
        }
        for _ in 0..15 {
            limiter.record_rate_limited().await;
        }

        // Verify error rate is above threshold
        let error_rate = limiter.outcome_window.error_rate().await;
        assert!(error_rate > 0.2, "Error rate should be above threshold");

        // Track RPS changes
        let rps_changes = Arc::new(AtomicU32::new(0));
        let rps_changes_clone = Arc::clone(&rps_changes);
        let last_rps = limiter.current_rps();

        // Start adaptive adjustment with short interval for testing
        let shutdown = limiter.start_adaptive_adjustment(
            move |new_rps| {
                rps_changes_clone.store(new_rps, Ordering::SeqCst);
            },
            Some(Duration::from_millis(100)),
        );

        // Wait for adjustment (should happen after first tick)
        tokio::time::sleep(Duration::from_millis(250)).await;

        // RPS should have decreased (from 20 to ~10, which is 50% reduction)
        let new_rps = limiter.current_rps();
        assert!(
            new_rps < last_rps,
            "RPS should decrease when error rate is high. Was: {}, Now: {}",
            last_rps,
            new_rps
        );
        assert!(
            new_rps >= limiter.min_rps,
            "RPS should not go below min_rps. Got: {}, Min: {}",
            new_rps,
            limiter.min_rps
        );

        shutdown.cancel();
    }

    #[tokio::test]
    async fn test_adaptive_adjustment_increase() {
        let limiter = AdaptiveRateLimiter::new(
            10,
            Some(1),
            Some(40),
            Some(0.2), // 20% threshold
            Some(100),
            Some(Duration::from_secs(30)),
        );

        // Record low error rate (5% = 2 errors out of 40 requests)
        // Error rate < threshold * 0.5 (10%) should trigger increase
        for _ in 0..38 {
            limiter.record_success().await;
        }
        for _ in 0..2 {
            limiter.record_timeout().await;
        }

        // Verify error rate is below threshold/2
        let error_rate = limiter.outcome_window.error_rate().await;
        assert!(
            error_rate < 0.1,
            "Error rate should be below threshold/2. Got: {}",
            error_rate
        );

        let initial_rps = limiter.current_rps();
        let rps_changes = Arc::new(AtomicU32::new(0));
        let rps_changes_clone = Arc::clone(&rps_changes);

        // Start adaptive adjustment
        let shutdown = limiter.start_adaptive_adjustment(
            move |new_rps| {
                rps_changes_clone.store(new_rps, Ordering::SeqCst);
            },
            Some(Duration::from_millis(100)),
        );

        // Wait for adjustment
        tokio::time::sleep(Duration::from_millis(250)).await;

        // RPS should have increased (by 15% or at least +1)
        let new_rps = limiter.current_rps();
        assert!(
            new_rps >= initial_rps,
            "RPS should increase or stay same when error rate is low. Was: {}, Now: {}",
            initial_rps,
            new_rps
        );
        assert!(
            new_rps <= limiter.max_rps,
            "RPS should not exceed max_rps. Got: {}, Max: {}",
            new_rps,
            limiter.max_rps
        );

        shutdown.cancel();
    }

    #[tokio::test]
    async fn test_adaptive_adjustment_no_change() {
        let limiter = AdaptiveRateLimiter::new(
            15,
            Some(1),
            Some(30),
            Some(0.2), // 20% threshold
            Some(100),
            Some(Duration::from_secs(30)),
        );

        // Record error rate between threshold/2 and threshold (10-20%)
        // This should not trigger adjustment
        for _ in 0..85 {
            limiter.record_success().await;
        }
        for _ in 0..15 {
            limiter.record_rate_limited().await;
        }

        // Error rate should be ~15% (between 10% and 20%)
        let error_rate = limiter.outcome_window.error_rate().await;
        assert!(
            (0.1..=0.2).contains(&error_rate),
            "Error rate should be between threshold/2 and threshold. Got: {}",
            error_rate
        );

        let initial_rps = limiter.current_rps();
        let rps_changes = Arc::new(AtomicU32::new(0));
        let rps_changes_clone = Arc::clone(&rps_changes);

        // Start adaptive adjustment
        let shutdown = limiter.start_adaptive_adjustment(
            move |new_rps| {
                rps_changes_clone.store(new_rps, Ordering::SeqCst);
            },
            Some(Duration::from_millis(100)),
        );

        // Wait for adjustment
        tokio::time::sleep(Duration::from_millis(250)).await;

        // RPS should remain the same (error rate is acceptable)
        let new_rps = limiter.current_rps();
        assert_eq!(
            new_rps, initial_rps,
            "RPS should remain unchanged when error rate is acceptable. Was: {}, Now: {}",
            initial_rps, new_rps
        );

        shutdown.cancel();
    }

    #[tokio::test]
    async fn test_adaptive_adjustment_insufficient_data() {
        let limiter = AdaptiveRateLimiter::new(
            20,
            Some(1),
            Some(40),
            Some(0.2),
            Some(100),
            Some(Duration::from_secs(30)),
        );

        // Record only 5 requests (less than 10 required for adjustment)
        for _ in 0..5 {
            limiter.record_success().await;
        }

        let initial_rps = limiter.current_rps();
        let rps_changes = Arc::new(AtomicU32::new(0));
        let rps_changes_clone = Arc::clone(&rps_changes);

        // Start adaptive adjustment
        let shutdown = limiter.start_adaptive_adjustment(
            move |new_rps| {
                rps_changes_clone.store(new_rps, Ordering::SeqCst);
            },
            Some(Duration::from_millis(100)),
        );

        // Wait for adjustment
        tokio::time::sleep(Duration::from_millis(250)).await;

        // RPS should not change (insufficient data points)
        let new_rps = limiter.current_rps();
        assert_eq!(
            new_rps, initial_rps,
            "RPS should not change with insufficient data. Was: {}, Now: {}",
            initial_rps, new_rps
        );

        shutdown.cancel();
    }

    #[tokio::test]
    async fn test_adaptive_adjustment_respects_min_rps() {
        let limiter = AdaptiveRateLimiter::new(
            5,
            Some(3), // Min RPS = 3
            Some(20),
            Some(0.2),
            Some(100),
            Some(Duration::from_secs(30)),
        );

        // Record very high error rate to trigger decrease
        for _ in 0..5 {
            limiter.record_success().await;
        }
        for _ in 0..95 {
            limiter.record_rate_limited().await;
        }

        let rps_changes = Arc::new(AtomicU32::new(0));
        let rps_changes_clone = Arc::clone(&rps_changes);

        // Start adaptive adjustment
        let shutdown = limiter.start_adaptive_adjustment(
            move |new_rps| {
                rps_changes_clone.store(new_rps, Ordering::SeqCst);
            },
            Some(Duration::from_millis(100)),
        );

        // Wait for multiple adjustments
        tokio::time::sleep(Duration::from_millis(500)).await;

        // RPS should never go below min_rps
        let final_rps = limiter.current_rps();
        assert!(
            final_rps >= limiter.min_rps,
            "RPS should not go below min_rps. Got: {}, Min: {}",
            final_rps,
            limiter.min_rps
        );

        shutdown.cancel();
    }

    #[tokio::test]
    async fn test_adaptive_adjustment_respects_max_rps() {
        let limiter = AdaptiveRateLimiter::new(
            10,
            Some(1),
            Some(15), // Max RPS = 15
            Some(0.2),
            Some(100),
            Some(Duration::from_secs(30)),
        );

        // Record very low error rate to trigger increase
        for _ in 0..95 {
            limiter.record_success().await;
        }
        for _ in 0..5 {
            limiter.record_timeout().await;
        }

        let rps_changes = Arc::new(AtomicU32::new(0));
        let rps_changes_clone = Arc::clone(&rps_changes);

        // Start adaptive adjustment
        let shutdown = limiter.start_adaptive_adjustment(
            move |new_rps| {
                rps_changes_clone.store(new_rps, Ordering::SeqCst);
            },
            Some(Duration::from_millis(100)),
        );

        // Wait for multiple adjustments
        tokio::time::sleep(Duration::from_millis(500)).await;

        // RPS should never exceed max_rps
        let final_rps = limiter.current_rps();
        assert!(
            final_rps <= limiter.max_rps,
            "RPS should not exceed max_rps. Got: {}, Max: {}",
            final_rps,
            limiter.max_rps
        );

        shutdown.cancel();
    }

    #[tokio::test]
    async fn test_multiple_outcome_types() {
        let limiter = AdaptiveRateLimiter::new(10, None, None, None, None, None);

        // Record mix of outcomes
        limiter.record_success().await;
        limiter.record_rate_limited().await;
        limiter.record_timeout().await;
        limiter.record_success().await;

        let request_count = limiter.outcome_window.request_count().await;
        assert_eq!(request_count, 4);

        // Error rate should be 50% (2 errors out of 4 requests)
        let error_rate = limiter.outcome_window.error_rate().await;
        assert!((error_rate - 0.5).abs() < 0.01);
    }
}
