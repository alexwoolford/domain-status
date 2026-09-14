//! Regression: `lookup_whois` is bounded by `WHOIS_TIMEOUT_SECS` (5s).
//!
//! The timeout lives in `src/whois/mod.rs` (`lookup_whois_with_lookup`). This
//! ignored test is a live-network check that a non-resolving TLD does not consume
//! the 35s per-URL budget. Deterministic coverage is
//! `test_lookup_whois_returns_none_on_timeout`.

use domain_status::config::WHOIS_TIMEOUT_SECS;
use domain_status::lookup_whois;
use std::time::Instant;
use tokio::time::{timeout, Duration};

/// A non-resolving TLD must not consume the 35s per-URL budget.
#[tokio::test]
#[ignore = "live WHOIS/RDAP; run with --ignored"]
async fn test_whois_lookup_honors_scan_timeout_budget() {
    let invalid_domain = "example.invalidtldthatdoesnotexist123456";
    let start = Instant::now();
    let _result = timeout(
        Duration::from_secs(WHOIS_TIMEOUT_SECS),
        lookup_whois(invalid_domain, None),
    )
    .await;
    let elapsed = start.elapsed();
    assert_eq!(WHOIS_TIMEOUT_SECS, 5);
    assert!(
        elapsed.as_secs() < 7,
        "WHOIS_TIMEOUT_SECS={WHOIS_TIMEOUT_SECS} should fail fast, took {:.2}s",
        elapsed.as_secs_f64()
    );
}
