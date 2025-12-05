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
/// * `total_urls` - Optional total number of URLs to process (for ETA calculation)
pub fn log_progress(
    start_time: std::time::Instant,
    completed_urls: &Arc<AtomicUsize>,
    total_urls: Option<&Arc<AtomicUsize>>,
) {
    let elapsed = start_time.elapsed();
    let completed = completed_urls.load(Ordering::SeqCst);
    let elapsed_secs = elapsed.as_secs_f64();
    let rate = if elapsed_secs > 0.0 {
        completed as f64 / elapsed_secs
    } else {
        0.0
    };

    // Calculate ETA and percentage if total URLs is known
    if let Some(total_arc) = total_urls {
        let total = total_arc.load(Ordering::SeqCst);
        if total > 0 {
            let percentage = (completed as f64 / total as f64) * 100.0;
            let remaining = total.saturating_sub(completed);

            let eta_secs = if rate > 0.0 && remaining > 0 {
                remaining as f64 / rate
            } else {
                0.0
            };

            let eta_duration = std::time::Duration::from_secs_f64(eta_secs);
            let eta_formatted = format_duration(eta_duration);

            info!(
                "Progress: {}/{} ({:.1}%) | Elapsed: {:.1}s | Rate: {:.2} lines/sec | ETA: {}",
                completed, total, percentage, elapsed_secs, rate, eta_formatted
            );
            return;
        }
    }

    // Fallback to simple format if total is unknown
    info!(
        "Processed {} lines in {:.2} seconds (~{:.2} lines/sec)",
        completed, elapsed_secs, rate
    );
}

/// Formats a duration in a human-readable format (e.g., "2h 15m 30s" or "45s").
fn format_duration(duration: std::time::Duration) -> String {
    let total_secs = duration.as_secs();

    if total_secs == 0 {
        return "< 1s".to_string();
    }

    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    match (hours, minutes, seconds) {
        (0, 0, s) => format!("{}s", s),
        (0, m, s) => format!("{}m {}s", m, s),
        (h, 0, 0) => format!("{}h", h),
        (h, m, 0) => format!("{}h {}m", h, m),
        (h, m, s) => format!("{}h {}m {}s", h, m, s),
    }
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
        log_progress(start_time, &completed_urls, None);
    }

    #[test]
    fn test_log_progress_with_completed() {
        let start_time = std::time::Instant::now();
        let completed_urls = Arc::new(AtomicUsize::new(100));
        completed_urls.store(100, Ordering::SeqCst);

        // Should not panic with completed URLs
        log_progress(start_time, &completed_urls, None);
    }

    #[test]
    fn test_log_progress_rate_calculation() {
        let start_time = std::time::Instant::now();
        let completed_urls = Arc::new(AtomicUsize::new(0));

        // Wait a small amount to ensure elapsed time > 0
        std::thread::sleep(Duration::from_millis(10));
        completed_urls.store(50, Ordering::SeqCst);

        // Should calculate rate correctly
        log_progress(start_time, &completed_urls, None);
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
        log_progress(start_time, &completed_urls, None);

        handle.join().unwrap();
        // Should not panic with concurrent updates
    }

    #[test]
    fn test_log_progress_with_total() {
        let start_time = std::time::Instant::now();
        let completed_urls = Arc::new(AtomicUsize::new(50));
        let total_urls = Arc::new(AtomicUsize::new(100));

        // Should calculate percentage and ETA
        log_progress(start_time, &completed_urls, Some(&total_urls));
    }

    #[test]
    fn test_log_progress_with_total_zero_completed() {
        let start_time = std::time::Instant::now();
        let completed_urls = Arc::new(AtomicUsize::new(0));
        let total_urls = Arc::new(AtomicUsize::new(100));

        // Should handle zero completed URLs with total
        log_progress(start_time, &completed_urls, Some(&total_urls));
    }

    #[test]
    fn test_log_progress_with_total_completed() {
        let start_time = std::time::Instant::now();
        let completed_urls = Arc::new(AtomicUsize::new(100));
        let total_urls = Arc::new(AtomicUsize::new(100));

        // Should handle 100% completion
        log_progress(start_time, &completed_urls, Some(&total_urls));
    }

    #[test]
    fn test_format_duration() {
        use super::format_duration;
        use std::time::Duration;

        assert_eq!(format_duration(Duration::from_secs(0)), "< 1s");
        assert_eq!(format_duration(Duration::from_secs(5)), "5s");
        assert_eq!(format_duration(Duration::from_secs(65)), "1m 5s");
        assert_eq!(format_duration(Duration::from_secs(3600)), "1h");
        assert_eq!(format_duration(Duration::from_secs(3665)), "1h 1m 5s");
        assert_eq!(format_duration(Duration::from_secs(7200)), "2h");
    }
}
