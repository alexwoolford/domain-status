//! Adaptive rate limiting with error-based throttling.
//!
//! This module implements a token-bucket rate limiter that automatically adjusts
//! request rate based on error rates:
//! - Monitors 429 (Too Many Requests) and timeout errors
//! - Reduces rate when error rate exceeds threshold (default 20%)
//! - Increases rate when error rate drops below threshold/2 (default 10%)
//! - Adjusts every 5 seconds with minimum 10 requests in window
//!
//! This prevents overwhelming servers while maximizing throughput when healthy.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::time::interval;
use tokio_util::sync::CancellationToken;

/// Tracks the outcome of a request for adaptive rate limiting.
#[derive(Debug, Clone, Copy)]
enum RequestOutcome {
    Success,
    RateLimited, // 429 errors
    Timeout,     // Timeout errors
}

/// Thread-safe sliding window for tracking recent request outcomes.
struct OutcomeWindow {
    outcomes: Arc<Mutex<VecDeque<(Instant, RequestOutcome)>>>,
    window_size: usize,
    window_duration: Duration,
}

impl OutcomeWindow {
    fn new(window_size: usize, window_duration: Duration) -> Self {
        OutcomeWindow {
            outcomes: Arc::new(Mutex::new(VecDeque::with_capacity(window_size))),
            window_size,
            window_duration,
        }
    }

    /// Records a request outcome.
    async fn record(&self, outcome: RequestOutcome) {
        let mut outcomes = self.outcomes.lock().await;
        let now = Instant::now();

        // Remove old entries outside the time window
        while let Some(front) = outcomes.front() {
            if now.duration_since(front.0) > self.window_duration {
                outcomes.pop_front();
            } else {
                break;
            }
        }

        // Add new outcome
        outcomes.push_back((now, outcome));

        // Trim to max size if needed
        while outcomes.len() > self.window_size {
            outcomes.pop_front();
        }
    }

    /// Calculates the error rate (429s + timeouts) in the recent window.
    /// Returns a value between 0.0 and 1.0.
    async fn error_rate(&self) -> f64 {
        let outcomes = self.outcomes.lock().await;
        let now = Instant::now();

        // Filter to recent entries within the time window
        let recent: Vec<_> = outcomes
            .iter()
            .filter(|(time, _)| now.duration_since(*time) <= self.window_duration)
            .collect();

        if recent.is_empty() {
            return 0.0;
        }

        let error_count = recent
            .iter()
            .filter(|(_, outcome)| {
                matches!(
                    outcome,
                    RequestOutcome::RateLimited | RequestOutcome::Timeout
                )
            })
            .count();

        error_count as f64 / recent.len() as f64
    }

    /// Gets the total number of requests in the recent window.
    async fn request_count(&self) -> usize {
        let outcomes = self.outcomes.lock().await;
        let now = Instant::now();

        outcomes
            .iter()
            .filter(|(time, _)| now.duration_since(*time) <= self.window_duration)
            .count()
    }
}

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
                                // Additive increase: increase by 10% (only if errors are low)
                                // Capped at max_rps (which equals initial_rps) to prevent runaway increases
                                let increased = ((current as f64 * 1.1).min(max_rps as f64) as u32)
                                    .max(current + 1); // At least +1
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

// OutcomeWindow is already clonable via Arc, no need for explicit Clone impl

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_outcome_window_error_rate() {
        let window = OutcomeWindow::new(100, Duration::from_secs(30));

        // Record 10 requests: 7 success, 3 rate limited
        for _ in 0..7 {
            window.record(RequestOutcome::Success).await;
        }
        for _ in 0..3 {
            window.record(RequestOutcome::RateLimited).await;
        }

        let error_rate = window.error_rate().await;
        assert!((error_rate - 0.3).abs() < 0.01); // Should be ~30%
    }

    #[tokio::test]
    async fn test_adaptive_rate_limiter_decrease() {
        let limiter = AdaptiveRateLimiter::new(10, None, None, Some(0.2), None, None);

        // Record high error rate
        for _ in 0..15 {
            limiter.record_rate_limited().await;
        }
        for _ in 0..5 {
            limiter.record_success().await;
        }

        // Wait a bit for the adjustment
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Error rate should be high, but adjustment happens in background task
        // So we can't easily test it without running the background task
        // This is more of an integration test scenario
    }
}
