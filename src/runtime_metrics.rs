use std::sync::atomic::{AtomicUsize, Ordering};

/// Live runtime counters for scan control-plane behavior.
#[derive(Default)]
pub struct RuntimeMetrics {
    retried_requests: AtomicUsize,
    non_retriable_failures: AtomicUsize,
    /// Rows successfully inserted into `url_partial_failures` this run.
    partial_failure_rows: AtomicUsize,
    /// Subset with `error_type` = `Satellite insert error`.
    satellite_insert_errors: AtomicUsize,
}

impl RuntimeMetrics {
    /// Record that a retryable failure consumed one retry attempt.
    pub fn record_retry(&self) {
        self.retried_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that a failure was classified as terminal/non-retriable.
    pub fn record_non_retriable_failure(&self) {
        self.non_retriable_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record persisted `url_partial_failures` rows (does not increment `failed_urls`).
    pub fn record_partial_failures(&self, rows: usize, satellite_insert_errors: usize) {
        if rows > 0 {
            self.partial_failure_rows.fetch_add(rows, Ordering::Relaxed);
        }
        if satellite_insert_errors > 0 {
            self.satellite_insert_errors
                .fetch_add(satellite_insert_errors, Ordering::Relaxed);
        }
    }

    /// Total retry attempts consumed by the runtime.
    pub fn retried_requests(&self) -> usize {
        self.retried_requests.load(Ordering::SeqCst)
    }

    /// Total failures classified as terminal at the retry boundary.
    pub fn non_retriable_failures(&self) -> usize {
        self.non_retriable_failures.load(Ordering::SeqCst)
    }

    /// Persisted `url_partial_failures` rows observed this run.
    pub fn partial_failure_rows(&self) -> usize {
        self.partial_failure_rows.load(Ordering::SeqCst)
    }

    /// Persisted satellite-insert SQL gaps this run.
    pub fn satellite_insert_errors(&self) -> usize {
        self.satellite_insert_errors.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::RuntimeMetrics;

    #[test]
    fn test_runtime_metrics_track_retries_and_terminal_failures() {
        let metrics = RuntimeMetrics::default();
        metrics.record_retry();
        metrics.record_retry();
        metrics.record_non_retriable_failure();

        assert_eq!(metrics.retried_requests(), 2);
        assert_eq!(metrics.non_retriable_failures(), 1);
    }

    #[test]
    fn test_runtime_metrics_track_partial_failures() {
        let metrics = RuntimeMetrics::default();
        metrics.record_partial_failures(3, 1);
        metrics.record_partial_failures(2, 2);
        assert_eq!(metrics.partial_failure_rows(), 5);
        assert_eq!(metrics.satellite_insert_errors(), 3);
    }
}
