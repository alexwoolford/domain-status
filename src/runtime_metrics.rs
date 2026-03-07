use std::sync::atomic::{AtomicUsize, Ordering};

/// Live runtime counters for scan control-plane behavior.
#[derive(Default)]
pub struct RuntimeMetrics {
    retried_requests: AtomicUsize,
    non_retriable_failures: AtomicUsize,
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

    /// Total retry attempts consumed by the runtime.
    pub fn retried_requests(&self) -> usize {
        self.retried_requests.load(Ordering::SeqCst)
    }

    /// Total failures classified as terminal at the retry boundary.
    pub fn non_retriable_failures(&self) -> usize {
        self.non_retriable_failures.load(Ordering::SeqCst)
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
}
