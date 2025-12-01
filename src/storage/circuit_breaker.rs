//! Circuit breaker for database write operations.
//!
//! Prevents resource exhaustion when database writes fail repeatedly.
//! After N consecutive failures, the circuit opens and stops attempting writes
//! until a cooldown period expires.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Circuit breaker state for database write operations.
///
/// Tracks consecutive failures and opens the circuit after a threshold.
/// The circuit automatically attempts to close after a cooldown period.
pub struct DbWriteCircuitBreaker {
    /// Number of consecutive failures before opening circuit
    failure_threshold: u32,
    /// Cooldown period before attempting to close circuit again
    cooldown_duration: Duration,
    /// Current consecutive failure count
    failure_count: Arc<AtomicU32>,
    /// Whether the circuit is currently open
    is_open: Arc<AtomicBool>,
    /// Timestamp when circuit was opened (for cooldown)
    opened_at: Arc<RwLock<Option<Instant>>>,
}

impl DbWriteCircuitBreaker {
    /// Creates a new circuit breaker with default settings.
    ///
    /// Defaults:
    /// - Failure threshold: 5 consecutive failures
    /// - Cooldown: 60 seconds
    pub fn new() -> Self {
        Self::with_threshold(5, Duration::from_secs(60))
    }

    /// Creates a new circuit breaker with custom settings.
    ///
    /// # Arguments
    ///
    /// * `failure_threshold` - Number of consecutive failures before opening circuit
    /// * `cooldown_duration` - How long to wait before attempting to close circuit
    pub fn with_threshold(failure_threshold: u32, cooldown_duration: Duration) -> Self {
        DbWriteCircuitBreaker {
            failure_threshold,
            cooldown_duration,
            failure_count: Arc::new(AtomicU32::new(0)),
            is_open: Arc::new(AtomicBool::new(false)),
            opened_at: Arc::new(RwLock::new(None)),
        }
    }

    /// Records a successful write operation.
    ///
    /// Resets the failure count and closes the circuit if it was open.
    pub async fn record_success(&self) {
        self.failure_count.store(0, Ordering::SeqCst);
        if self.is_open.load(Ordering::SeqCst) {
            self.is_open.store(false, Ordering::SeqCst);
            *self.opened_at.write().await = None;
            log::info!("Database write circuit breaker: circuit closed after successful write");
        }
    }

    /// Records a failed write operation.
    ///
    /// Increments the failure count and opens the circuit if threshold is reached.
    pub async fn record_failure(&self) {
        let count = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;

        if count >= self.failure_threshold && !self.is_open.load(Ordering::SeqCst) {
            self.is_open.store(true, Ordering::SeqCst);
            *self.opened_at.write().await = Some(Instant::now());
            log::error!(
                "Database write circuit breaker: circuit opened after {} consecutive failures (cooldown: {}s)",
                count,
                self.cooldown_duration.as_secs()
            );
        }
    }

    /// Checks if the circuit is open (writes should be blocked).
    ///
    /// Returns `true` if the circuit is open and cooldown hasn't expired.
    /// Returns `false` if the circuit is closed or cooldown has expired (allowing retry).
    pub async fn is_circuit_open(&self) -> bool {
        if !self.is_open.load(Ordering::SeqCst) {
            return false;
        }

        // Check if cooldown period has expired
        let opened_at = self.opened_at.read().await;
        if let Some(opened) = *opened_at {
            if opened.elapsed() >= self.cooldown_duration {
                // Cooldown expired, allow one attempt to close circuit
                log::info!(
                    "Database write circuit breaker: cooldown expired, attempting to close circuit"
                );
                self.is_open.store(false, Ordering::SeqCst);
                return false;
            }
        }

        true
    }

    /// Gets the current failure count (for monitoring).
    #[allow(dead_code)] // Reserved for future monitoring/metrics
    pub fn failure_count(&self) -> u32 {
        self.failure_count.load(Ordering::SeqCst)
    }

    /// Gets whether the circuit is currently open (for monitoring).
    #[allow(dead_code)] // Reserved for future monitoring/metrics
    pub fn is_open(&self) -> bool {
        self.is_open.load(Ordering::SeqCst)
    }
}

impl Default for DbWriteCircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_circuit_breaker_opens_after_threshold() {
        let cb = DbWriteCircuitBreaker::with_threshold(3, Duration::from_millis(100));

        // Record 2 failures - circuit should still be closed
        cb.record_failure().await;
        cb.record_failure().await;
        assert!(!cb.is_circuit_open().await);
        assert_eq!(cb.failure_count(), 2);

        // Record 3rd failure - circuit should open
        cb.record_failure().await;
        assert!(cb.is_circuit_open().await);
        assert_eq!(cb.failure_count(), 3);
    }

    #[tokio::test]
    async fn test_circuit_breaker_resets_on_success() {
        let cb = DbWriteCircuitBreaker::with_threshold(3, Duration::from_millis(100));

        // Record 2 failures
        cb.record_failure().await;
        cb.record_failure().await;
        assert_eq!(cb.failure_count(), 2);

        // Record success - should reset
        cb.record_success().await;
        assert_eq!(cb.failure_count(), 0);
        assert!(!cb.is_circuit_open().await);
    }

    #[tokio::test]
    async fn test_circuit_breaker_cooldown() {
        let cb = DbWriteCircuitBreaker::with_threshold(2, Duration::from_millis(50));

        // Open circuit
        cb.record_failure().await;
        cb.record_failure().await;
        assert!(cb.is_circuit_open().await);

        // Wait for cooldown
        sleep(Duration::from_millis(60)).await;

        // Circuit should allow retry (closed)
        assert!(!cb.is_circuit_open().await);
    }
}
