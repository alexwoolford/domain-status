//! Progress logging utilities.

use log::info;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Logs progress information about URL processing.
///
/// Progress and ETA are based on finished work
/// (`successful + failed + skipped`) against the input file total when provided.
///
/// # Arguments
///
/// * `start_time` - The start time of processing
/// * `successful_urls` - Atomic counter of successfully persisted URLs
/// * `failed_urls` - Atomic counter of failed URLs
/// * `skipped_urls` - Atomic counter of skipped URLs
/// * `total_urls` - Optional total URLs in the input file (for ETA / %)
pub fn log_progress(
    start_time: std::time::Instant,
    successful_urls: &Arc<AtomicUsize>,
    failed_urls: &Arc<AtomicUsize>,
    skipped_urls: &Arc<AtomicUsize>,
    total_urls: Option<&Arc<AtomicUsize>>,
) {
    let elapsed = start_time.elapsed();
    let successful = successful_urls.load(Ordering::SeqCst);
    let failed = failed_urls.load(Ordering::SeqCst);
    let skipped = skipped_urls.load(Ordering::SeqCst);
    let finished = successful + failed + skipped;
    let elapsed_secs = elapsed.as_secs_f64();
    // Safe cast: URL counts typically < 1M, well within f64 precision
    #[allow(clippy::cast_precision_loss)]
    let rate = if elapsed_secs > 0.0 {
        finished as f64 / elapsed_secs
    } else {
        0.0
    };

    if let Some(total_arc) = total_urls {
        let total = total_arc.load(Ordering::SeqCst);
        if total > 0 {
            #[allow(clippy::cast_precision_loss)]
            let percentage = (finished as f64 / total as f64) * 100.0;
            let remaining = total.saturating_sub(finished);

            #[allow(clippy::cast_precision_loss)]
            let eta_secs = if rate > 0.0 && remaining > 0 {
                remaining as f64 / rate
            } else {
                0.0
            };

            let eta_duration = std::time::Duration::from_secs_f64(eta_secs);
            let eta_formatted = format_duration(eta_duration);

            info!(
                "Progress: {finished}/{total} ({percentage:.1}%) | Succeeded: {successful} | Failed: {failed} | Skipped: {skipped} | Elapsed: {elapsed_secs:.1}s | Rate: {rate:.2} lines/sec | ETA: {eta_formatted}"
            );
            return;
        }
    }

    info!(
        "Processed {finished} lines ({successful} succeeded, {failed} failed, {skipped} skipped) in {elapsed_secs:.2} seconds (~{rate:.2} lines/sec)"
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
        (0, 0, s) => format!("{s}s"),
        (0, m, s) => format!("{m}m {s}s"),
        (h, 0, 0) => format!("{h}h"),
        (h, m, 0) => format!("{h}h {m}m"),
        (h, m, s) => format!("{h}h {m}m {s}s"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    #[test]
    fn test_log_progress_zero_completed() {
        let start_time = std::time::Instant::now();
        let successful_urls = Arc::new(AtomicUsize::new(0));
        let failed_urls = Arc::new(AtomicUsize::new(0));
        let skipped_urls = Arc::new(AtomicUsize::new(0));

        log_progress(
            start_time,
            &successful_urls,
            &failed_urls,
            &skipped_urls,
            None,
        );
    }

    #[test]
    fn test_log_progress_with_completed() {
        let start_time = std::time::Instant::now();
        let successful_urls = Arc::new(AtomicUsize::new(100));
        let failed_urls = Arc::new(AtomicUsize::new(0));
        let skipped_urls = Arc::new(AtomicUsize::new(0));

        log_progress(
            start_time,
            &successful_urls,
            &failed_urls,
            &skipped_urls,
            None,
        );
    }

    #[test]
    fn test_log_progress_with_total() {
        let start_time = std::time::Instant::now();
        let successful_urls = Arc::new(AtomicUsize::new(50));
        let failed_urls = Arc::new(AtomicUsize::new(10));
        let skipped_urls = Arc::new(AtomicUsize::new(0));
        let total_urls = Arc::new(AtomicUsize::new(100));

        log_progress(
            start_time,
            &successful_urls,
            &failed_urls,
            &skipped_urls,
            Some(&total_urls),
        );
    }

    #[test]
    fn test_log_progress_includes_skipped_in_finished() {
        let start_time = std::time::Instant::now();
        let successful_urls = Arc::new(AtomicUsize::new(40));
        let failed_urls = Arc::new(AtomicUsize::new(10));
        let skipped_urls = Arc::new(AtomicUsize::new(10));
        let total_urls = Arc::new(AtomicUsize::new(100));

        // Should treat finished as 60/100 without panicking
        log_progress(
            start_time,
            &successful_urls,
            &failed_urls,
            &skipped_urls,
            Some(&total_urls),
        );
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
