//! Shared progress math for `/status` and `/metrics`.
//!
//! Finished work is `successful + failed + skipped` (matches finalize / `runs`).

use std::sync::atomic::Ordering;

use super::types::StatusState;

/// Snapshot of progress counters derived from [`StatusState`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ProgressSnapshot {
    pub total_urls: usize,
    pub attempted: usize,
    pub successful: usize,
    pub failed: usize,
    pub skipped: usize,
    pub finished: usize,
    pub active_urls: usize,
    pub pending_urls: usize,
    pub percentage_complete: f64,
    pub percentage_dispatched: f64,
    pub rate_per_second: f64,
    pub eta_seconds: Option<f64>,
}

/// Load counters and derive active / percent / rate / ETA.
pub fn progress_snapshot(state: &StatusState, elapsed: f64) -> ProgressSnapshot {
    let total_urls = state.total_urls.load(Ordering::SeqCst);
    let attempted = state.total_urls_attempted.load(Ordering::SeqCst);
    let successful = state.successful_urls.load(Ordering::SeqCst);
    let failed = state.failed_urls.load(Ordering::SeqCst);
    let skipped = state.skipped_urls.load(Ordering::SeqCst);
    let finished = successful.saturating_add(failed).saturating_add(skipped);
    let active_urls = attempted.saturating_sub(finished);
    let pending_urls = total_urls.saturating_sub(attempted);

    #[allow(clippy::cast_precision_loss)]
    let percentage_complete = if total_urls > 0 {
        (finished as f64 / total_urls as f64) * 100.0
    } else {
        0.0
    };
    #[allow(clippy::cast_precision_loss)]
    let percentage_dispatched = if total_urls > 0 {
        (attempted as f64 / total_urls as f64) * 100.0
    } else {
        0.0
    };
    #[allow(clippy::cast_precision_loss)]
    let rate_per_second = if elapsed > 0.0 {
        finished as f64 / elapsed
    } else {
        0.0
    };

    let remaining = total_urls.saturating_sub(finished);
    #[allow(clippy::cast_precision_loss)]
    let eta_seconds = if remaining > 0 && rate_per_second > 0.0 {
        Some(remaining as f64 / rate_per_second)
    } else if remaining == 0 && total_urls > 0 {
        Some(0.0)
    } else {
        None
    };

    ProgressSnapshot {
        total_urls,
        attempted,
        successful,
        failed,
        skipped,
        finished,
        active_urls,
        pending_urls,
        percentage_complete,
        percentage_dispatched,
        rate_per_second,
        eta_seconds,
    }
}

/// Current scan phase label for JSON / Prometheus.
pub fn phase_label(state: &StatusState) -> &'static str {
    state.phase.get().as_str()
}

/// In-flight tasks inferred from semaphore permits when available.
pub fn concurrency_in_use(state: &StatusState) -> Option<usize> {
    let max = state.max_concurrency?;
    let sem = state.semaphore.as_ref()?;
    Some(max.saturating_sub(sem.available_permits()))
}
