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
    /// Uses atomic compare-and-swap to prevent race conditions when opening the circuit.
    pub async fn record_failure(&self) {
        let count = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;

        if count >= self.failure_threshold {
            // Use compare-and-swap to atomically check and set is_open
            // This prevents race conditions where multiple threads try to open the circuit simultaneously
            let was_closed = self
                .is_open
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok();

            if was_closed {
                // Only one thread will successfully open the circuit
                *self.opened_at.write().await = Some(Instant::now());
                log::error!(
                    "Database write circuit breaker: circuit opened after {} consecutive failures (cooldown: {}s)",
                    count,
                    self.cooldown_duration.as_secs()
                );
            }
        }
    }

    /// Checks if the circuit is open (writes should be blocked).
    ///
    /// Returns `true` if the circuit is open and cooldown hasn't expired.
    /// Returns `false` if the circuit is closed or cooldown has expired (allowing retry).
    ///
    /// This method uses a read lock to atomically check both `is_open` and `opened_at`
    /// to prevent race conditions where the circuit state could change between checks.
    pub async fn is_circuit_open(&self) -> bool {
        // Fast path: if circuit is not open, return immediately
        if !self.is_open.load(Ordering::SeqCst) {
            return false;
        }

        // Slow path: check cooldown with proper synchronization
        // Use write lock to atomically check and update state to prevent race conditions
        let mut opened_at = self.opened_at.write().await;
        if let Some(opened) = *opened_at {
            if opened.elapsed() >= self.cooldown_duration {
                // Cooldown expired, allow one attempt to close circuit
                // Atomically update both is_open and opened_at
                self.is_open.store(false, Ordering::SeqCst);
                *opened_at = None;
                log::info!(
                    "Database write circuit breaker: cooldown expired, attempting to close circuit"
                );
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

    /// Gets whether the circuit is currently open (for monitoring/testing only).
    ///
    /// # Note
    /// This method is synchronous and does not check cooldown expiration.
    /// For production code, use `is_circuit_open()` which properly handles cooldown.
    /// This method is primarily for testing and monitoring.
    #[allow(dead_code)] // Reserved for future monitoring/metrics
    pub fn is_open_sync(&self) -> bool {
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

    /// Helper function to wait for circuit breaker to reach expected state.
    ///
    /// Polls the circuit state with exponential backoff to handle async lock acquisition
    /// timing issues on different platforms (especially Windows CI).
    ///
    /// # Arguments
    /// * `cb` - Circuit breaker to check
    /// * `expected_open` - Expected state (true = open, false = closed)
    /// * `timeout` - Maximum time to wait
    ///
    /// # Panics
    /// Panics if timeout is reached before reaching expected state
    async fn wait_for_circuit_state(
        cb: &DbWriteCircuitBreaker,
        expected_open: bool,
        timeout: Duration,
    ) {
        let start = Instant::now();
        let mut delay = Duration::from_micros(100);
        const MAX_DELAY: Duration = Duration::from_millis(10);

        loop {
            // Yield to scheduler first to allow other tasks to run (helps under heavy test load)
            tokio::task::yield_now().await;

            if cb.is_circuit_open().await == expected_open {
                return; // Success
            }

            if start.elapsed() >= timeout {
                panic!(
                    "Timeout waiting for circuit to be {} (timeout: {:?}). State: is_open={}, count={}",
                    if expected_open { "open" } else { "closed" },
                    timeout,
                    cb.is_open_sync(),
                    cb.failure_count()
                );
            }

            // Exponential backoff to reduce CPU usage while waiting
            sleep(delay).await;
            delay = (delay * 2).min(MAX_DELAY);
        }
    }

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

        // Wait for circuit to fully open
        wait_for_circuit_state(&cb, true, Duration::from_millis(500)).await;

        // Wait for cooldown
        sleep(Duration::from_millis(60)).await;

        // Circuit should allow retry (closed)
        wait_for_circuit_state(&cb, false, Duration::from_millis(500)).await;
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_exactly_at_threshold() {
        let cb = DbWriteCircuitBreaker::with_threshold(3, Duration::from_millis(100));

        // Record failures up to threshold - 1
        cb.record_failure().await;
        cb.record_failure().await;
        assert!(!cb.is_circuit_open().await);
        assert_eq!(cb.failure_count(), 2);

        // Record threshold failure - should open
        cb.record_failure().await;
        assert!(cb.is_circuit_open().await);
        assert_eq!(cb.failure_count(), 3);
    }

    #[tokio::test]
    async fn test_circuit_breaker_multiple_open_close_cycles() {
        let cb = DbWriteCircuitBreaker::with_threshold(2, Duration::from_millis(50));

        // First cycle: open
        cb.record_failure().await;
        cb.record_failure().await;
        wait_for_circuit_state(&cb, true, Duration::from_millis(500)).await;

        // Wait for cooldown
        sleep(Duration::from_millis(60)).await;
        wait_for_circuit_state(&cb, false, Duration::from_millis(500)).await;

        // Second cycle: open again
        cb.record_failure().await;
        cb.record_failure().await;
        wait_for_circuit_state(&cb, true, Duration::from_millis(500)).await;

        // Wait for cooldown again
        sleep(Duration::from_millis(60)).await;
        wait_for_circuit_state(&cb, false, Duration::from_millis(500)).await;
    }

    #[tokio::test]
    async fn test_circuit_breaker_success_closes_open_circuit() {
        let cb = DbWriteCircuitBreaker::with_threshold(2, Duration::from_millis(100));

        // Open circuit
        cb.record_failure().await;
        cb.record_failure().await;
        wait_for_circuit_state(&cb, true, Duration::from_millis(500)).await;

        // Record success - should close circuit immediately
        cb.record_success().await;
        wait_for_circuit_state(&cb, false, Duration::from_millis(500)).await;
        assert_eq!(cb.failure_count(), 0);
    }

    #[tokio::test]
    async fn test_circuit_breaker_success_resets_count_before_threshold() {
        let cb = DbWriteCircuitBreaker::with_threshold(5, Duration::from_millis(100));

        // Record some failures
        cb.record_failure().await;
        cb.record_failure().await;
        cb.record_failure().await;
        assert_eq!(cb.failure_count(), 3);
        assert!(!cb.is_circuit_open().await);

        // Record success - should reset count
        cb.record_success().await;
        assert_eq!(cb.failure_count(), 0);
        assert!(!cb.is_circuit_open().await);

        // Can accumulate failures again from zero
        cb.record_failure().await;
        assert_eq!(cb.failure_count(), 1);
    }

    #[tokio::test]
    async fn test_circuit_breaker_cooldown_not_expired() {
        let cb = DbWriteCircuitBreaker::with_threshold(2, Duration::from_millis(100));

        // Open circuit
        cb.record_failure().await;
        cb.record_failure().await;
        wait_for_circuit_state(&cb, true, Duration::from_millis(500)).await;

        // Wait less than cooldown
        sleep(Duration::from_millis(50)).await;

        // Circuit should still be open
        assert!(cb.is_circuit_open().await);
    }

    #[tokio::test]
    async fn test_circuit_breaker_default_creation() {
        let cb = DbWriteCircuitBreaker::new();

        // Verify initial state
        assert_eq!(cb.failure_count(), 0);
        assert!(!cb.is_circuit_open().await);
        assert!(!cb.is_open_sync());
    }

    #[tokio::test]
    async fn test_circuit_breaker_custom_threshold() {
        let cb = DbWriteCircuitBreaker::with_threshold(10, Duration::from_secs(30));

        // Record 9 failures - should still be closed
        for _ in 0..9 {
            cb.record_failure().await;
        }
        assert!(!cb.is_circuit_open().await);
        assert_eq!(cb.failure_count(), 9);

        // Record 10th failure - should open
        cb.record_failure().await;
        assert!(cb.is_circuit_open().await);
        assert_eq!(cb.failure_count(), 10);
    }

    #[tokio::test]
    async fn test_circuit_breaker_failure_after_cooldown_expires() {
        let cb = DbWriteCircuitBreaker::with_threshold(2, Duration::from_millis(50));

        // Open circuit
        cb.record_failure().await;
        cb.record_failure().await;
        assert_eq!(cb.failure_count(), 2);

        // Wait for circuit to fully open (handles async lock acquisition on slower systems)
        wait_for_circuit_state(&cb, true, Duration::from_millis(500)).await;

        // Wait for cooldown
        sleep(Duration::from_millis(60)).await;

        // Wait for circuit to close after cooldown
        wait_for_circuit_state(&cb, false, Duration::from_millis(500)).await;

        // Record another failure - count continues from previous (doesn't reset on cooldown)
        cb.record_failure().await;
        // Failure count continues: was 2, now 3
        assert_eq!(cb.failure_count(), 3);

        // Wait for circuit to open again (threshold is 2, we now have 3)
        wait_for_circuit_state(&cb, true, Duration::from_millis(500)).await;
    }
}
