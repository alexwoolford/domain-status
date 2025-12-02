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

