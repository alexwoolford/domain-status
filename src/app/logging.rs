//! Progress logging utilities.

use log::info;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Logs progress information about URL processing.
///
/// # Arguments
///
/// * `start_time` - The start time of processing
/// * `completed_urls` - Atomic counter of completed URLs
pub fn log_progress(start_time: std::time::Instant, completed_urls: &Arc<AtomicUsize>) {
    let elapsed = start_time.elapsed();
    let completed = completed_urls.load(Ordering::SeqCst);
    let elapsed_secs = elapsed.as_secs_f64();
    let rate = if elapsed_secs > 0.0 {
        completed as f64 / elapsed_secs
    } else {
        0.0
    };
    info!(
        "Processed {} lines in {:.2} seconds (~{:.2} lines/sec)",
        completed, elapsed_secs, rate
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn test_log_progress_zero_completed() {
        let start_time = std::time::Instant::now();
        let completed_urls = Arc::new(AtomicUsize::new(0));

        // Should not panic with zero completed URLs
        log_progress(start_time, &completed_urls);
    }

    #[test]
    fn test_log_progress_with_completed() {
        let start_time = std::time::Instant::now();
        let completed_urls = Arc::new(AtomicUsize::new(100));
        completed_urls.store(100, Ordering::SeqCst);

        // Should not panic with completed URLs
        log_progress(start_time, &completed_urls);
    }

    #[test]
    fn test_log_progress_rate_calculation() {
        let start_time = std::time::Instant::now();
        let completed_urls = Arc::new(AtomicUsize::new(0));

        // Wait a small amount to ensure elapsed time > 0
        std::thread::sleep(Duration::from_millis(10));
        completed_urls.store(50, Ordering::SeqCst);

        // Should calculate rate correctly
        log_progress(start_time, &completed_urls);
    }

    #[test]
    fn test_log_progress_concurrent_updates() {
        use std::thread;

        let start_time = std::time::Instant::now();
        let completed_urls = Arc::new(AtomicUsize::new(0));

        // Simulate concurrent updates
        let urls_clone = Arc::clone(&completed_urls);
        let handle = thread::spawn(move || {
            for _ in 0..10 {
                urls_clone.fetch_add(1, Ordering::SeqCst);
            }
        });

        // Call log_progress while updates are happening
        log_progress(start_time, &completed_urls);

        handle.join().unwrap();
        // Should not panic with concurrent updates
    }
}
