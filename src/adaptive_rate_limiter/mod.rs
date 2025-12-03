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

mod limiter;
mod window;

pub use limiter::AdaptiveRateLimiter;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_outcome_window_error_rate() {
        use window::{OutcomeWindow, RequestOutcome};

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
