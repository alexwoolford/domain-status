//! Sliding window for tracking request outcomes.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Tracks the outcome of a request for adaptive rate limiting.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RequestOutcome {
    Success,
    RateLimited, // 429 errors
    Timeout,     // Timeout errors
}

/// Thread-safe sliding window for tracking recent request outcomes.
pub(crate) struct OutcomeWindow {
    pub(crate) outcomes: Arc<Mutex<VecDeque<(Instant, RequestOutcome)>>>,
    pub(crate) window_size: usize,
    pub(crate) window_duration: Duration,
}

impl OutcomeWindow {
    pub(crate) fn new(window_size: usize, window_duration: Duration) -> Self {
        OutcomeWindow {
            outcomes: Arc::new(Mutex::new(VecDeque::with_capacity(window_size))),
            window_size,
            window_duration,
        }
    }

    /// Records a request outcome.
    pub(crate) async fn record(&self, outcome: RequestOutcome) {
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
    pub(crate) async fn error_rate(&self) -> f64 {
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
    pub(crate) async fn request_count(&self) -> usize {
        let outcomes = self.outcomes.lock().await;
        let now = Instant::now();

        outcomes
            .iter()
            .filter(|(time, _)| now.duration_since(*time) <= self.window_duration)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration as TokioDuration};

    #[tokio::test]
    async fn test_outcome_window_record_success() {
        let window = OutcomeWindow::new(100, Duration::from_secs(30));

        window.record(RequestOutcome::Success).await;

        assert_eq!(window.request_count().await, 1);
        assert_eq!(window.error_rate().await, 0.0);
    }

    #[tokio::test]
    async fn test_outcome_window_record_rate_limited() {
        let window = OutcomeWindow::new(100, Duration::from_secs(30));

        window.record(RequestOutcome::RateLimited).await;

        assert_eq!(window.request_count().await, 1);
        assert_eq!(window.error_rate().await, 1.0); // 100% error rate
    }

    #[tokio::test]
    async fn test_outcome_window_record_timeout() {
        let window = OutcomeWindow::new(100, Duration::from_secs(30));

        window.record(RequestOutcome::Timeout).await;

        assert_eq!(window.request_count().await, 1);
        assert_eq!(window.error_rate().await, 1.0); // 100% error rate
    }

    #[tokio::test]
    async fn test_outcome_window_error_rate_mixed() {
        let window = OutcomeWindow::new(100, Duration::from_secs(30));

        // Record 2 successes, 2 errors
        window.record(RequestOutcome::Success).await;
        window.record(RequestOutcome::Success).await;
        window.record(RequestOutcome::RateLimited).await;
        window.record(RequestOutcome::Timeout).await;

        assert_eq!(window.request_count().await, 4);
        assert_eq!(window.error_rate().await, 0.5); // 2 errors / 4 requests = 50%
    }

    #[tokio::test]
    async fn test_outcome_window_error_rate_only_success() {
        let window = OutcomeWindow::new(100, Duration::from_secs(30));

        window.record(RequestOutcome::Success).await;
        window.record(RequestOutcome::Success).await;
        window.record(RequestOutcome::Success).await;

        assert_eq!(window.error_rate().await, 0.0);
    }

    #[tokio::test]
    async fn test_outcome_window_error_rate_only_errors() {
        let window = OutcomeWindow::new(100, Duration::from_secs(30));

        window.record(RequestOutcome::RateLimited).await;
        window.record(RequestOutcome::Timeout).await;
        window.record(RequestOutcome::RateLimited).await;

        assert_eq!(window.error_rate().await, 1.0); // 100% error rate
    }

    #[tokio::test]
    async fn test_outcome_window_empty_error_rate() {
        let window = OutcomeWindow::new(100, Duration::from_secs(30));

        // No records yet
        assert_eq!(window.error_rate().await, 0.0);
        assert_eq!(window.request_count().await, 0);
    }

    #[tokio::test]
    async fn test_outcome_window_size_limit() {
        let window = OutcomeWindow::new(5, Duration::from_secs(30));

        // Record more than the window size
        for _ in 0..10 {
            window.record(RequestOutcome::Success).await;
        }

        // Should be trimmed to window size
        assert_eq!(window.request_count().await, 5);
    }

    #[tokio::test]
    async fn test_outcome_window_time_expiration() {
        let window = OutcomeWindow::new(100, Duration::from_millis(50));

        // Record some outcomes
        window.record(RequestOutcome::Success).await;
        window.record(RequestOutcome::RateLimited).await;

        assert_eq!(window.request_count().await, 2);

        // Wait for window to expire
        sleep(TokioDuration::from_millis(60)).await;

        // Old entries should be removed
        assert_eq!(window.request_count().await, 0);
        assert_eq!(window.error_rate().await, 0.0);
    }

    #[tokio::test]
    async fn test_outcome_window_partial_expiration() {
        let window = OutcomeWindow::new(100, Duration::from_millis(100));

        // Record outcomes
        window.record(RequestOutcome::Success).await;
        window.record(RequestOutcome::RateLimited).await;

        // Wait partway through window
        sleep(TokioDuration::from_millis(50)).await;

        // Record more outcomes
        window.record(RequestOutcome::Success).await;
        window.record(RequestOutcome::Timeout).await;

        // All 4 should still be in window
        assert_eq!(window.request_count().await, 4);

        // Wait for first two to expire (50ms + 60ms = 110ms > 100ms window)
        sleep(TokioDuration::from_millis(60)).await;

        // Only last 2 should remain (Success and Timeout)
        assert_eq!(window.request_count().await, 2);
        // One error (Timeout) out of 2 = 50% error rate
        let error_rate = window.error_rate().await;
        assert!(
            (error_rate - 0.5).abs() < 0.01,
            "Expected ~0.5, got {}",
            error_rate
        );
    }

    #[tokio::test]
    async fn test_outcome_window_size_and_time_trimming() {
        let window = OutcomeWindow::new(3, Duration::from_millis(100));

        // Fill window to capacity
        window.record(RequestOutcome::Success).await;
        window.record(RequestOutcome::Success).await;
        window.record(RequestOutcome::Success).await;

        assert_eq!(window.request_count().await, 3);

        // Add one more - should trim oldest
        window.record(RequestOutcome::RateLimited).await;

        // Should still be 3 (trimmed by size)
        assert_eq!(window.request_count().await, 3);
        // One error out of 3 = 33.3% error rate
        let error_rate = window.error_rate().await;
        assert!(
            (error_rate - 0.333).abs() < 0.01,
            "Expected ~0.333, got {}",
            error_rate
        );
    }

    #[tokio::test]
    async fn test_outcome_window_new_creation() {
        let window = OutcomeWindow::new(50, Duration::from_secs(60));

        // Verify initial state
        assert_eq!(window.request_count().await, 0);
        assert_eq!(window.error_rate().await, 0.0);
    }
}
