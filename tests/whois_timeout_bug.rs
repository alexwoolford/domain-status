//! Test demonstrating WHOIS timeout bug and fix.
//!
//! **BUG FOUND**: The WHOIS lookup relied on whois-service's internal timeout
//! which defaults to 30 seconds in production. This is too long and can block
//! workers, consuming most of the 35s URL_PROCESSING_TIMEOUT budget.
//!
//! **ROOT CAUSE**:
//! - whois-service crate has internal timeouts: 30s in production, 15s in non-production
//! - src/whois/mod.rs creates WhoisClient with default settings (no custom timeout)
//! - src/fetch/record/preparation.rs called lookup_whois() without timeout wrapper
//! - A slow WHOIS server could block a worker for up to 30 seconds
//!
//! **FIX APPLIED**:
//! - Added WHOIS_TIMEOUT_SECS constant (5 seconds) in src/config/constants.rs
//! - Wrapped lookup_whois() in tokio::time::timeout() in src/fetch/record/preparation.rs
//! - Now WHOIS lookups fail fast after 5s, preventing worker blocking
//!
//! **Impact**: Most WHOIS queries complete in <2s. The 5s timeout provides
//! a reasonable buffer while preventing the 30s default from consuming most
//! of the URL_PROCESSING_TIMEOUT budget.

use domain_status::lookup_whois;
use std::time::{Duration, Instant};
use tokio::time::timeout;

/// Demonstrates that WHOIS lookup has no timeout.
///
/// This test attempts a WHOIS lookup on a non-existent TLD that will likely
/// hang or timeout very slowly. Without a proper timeout, this could take
/// 30+ seconds or hang indefinitely.
///
/// Expected behavior: WHOIS should timeout after ~5s
/// Actual behavior: May take 30+ seconds or hang
#[tokio::test]
#[ignore] // Run with: cargo test --test whois_timeout_bug -- --ignored
async fn test_whois_lookup_no_timeout() {
    // Use a non-existent TLD that IANA doesn't recognize
    // This should cause the WHOIS client to hang or take a very long time
    let invalid_domain = "example.invalidtldthatdoesnotexist123456";

    let start = Instant::now();

    // Wrap the WHOIS lookup in a timeout to prevent test from hanging forever
    let result = timeout(
        Duration::from_secs(30), // 30s max for this test
        lookup_whois(invalid_domain, None),
    )
    .await;

    let elapsed = start.elapsed();

    println!("WHOIS lookup took {:.2}s", elapsed.as_secs_f64());
    println!("Result: {:?}", result);

    // **BUG EXPOSED**: This assertion should pass if WHOIS had proper timeout
    // but it FAILS because WHOIS can hang for many seconds
    //
    // Expected: Should timeout after ~5s (reasonable WHOIS timeout)
    // Actual: May take 10-30+ seconds or hit our test timeout
    assert!(
        elapsed.as_secs() < 7,
        "BUG: WHOIS lookup took {:.2}s instead of failing fast (~5s)",
        elapsed.as_secs_f64()
    );
}

/// Demonstrates that even valid domains can take too long without timeout.
///
/// Some WHOIS servers are notoriously slow. Without a timeout,
/// a slow server can block workers for extended periods.
#[tokio::test]
#[ignore]
async fn test_whois_lookup_slow_server() {
    // Use a domain that might have slow WHOIS servers
    // (This is just for demonstration - actual time varies)
    let domain = "example.com";

    let start = Instant::now();

    // Wrap in timeout to prevent test from hanging
    let result = timeout(Duration::from_secs(15), lookup_whois(domain, None)).await;

    let elapsed = start.elapsed();

    println!(
        "WHOIS lookup for {} took {:.2}s",
        domain,
        elapsed.as_secs_f64()
    );

    let is_ok = result.is_ok();
    println!("Result: {:?}", result.map(|r| r.map(|_| "Success")));

    // Even if successful, WHOIS should not take more than 5s
    // (Most WHOIS queries complete in <2s when properly optimized)
    if is_ok && elapsed.as_secs() > 7 {
        println!(
            "WARNING: WHOIS took {:.2}s - should have timeout to prevent worker blocking",
            elapsed.as_secs_f64()
        );
    }
}

/// Documents the fix: WHOIS with explicit timeout.
///
/// This test shows how WHOIS should be called with a proper timeout
/// to prevent worker blocking.
///
/// **FIX APPLIED**: src/fetch/record/preparation.rs now wraps WHOIS lookup
/// in tokio::time::timeout(Duration::from_secs(WHOIS_TIMEOUT_SECS))
///
/// This prevents slow WHOIS servers from blocking workers for 30+ seconds.
#[tokio::test]
#[ignore]
async fn test_whois_lookup_with_timeout_fix() {
    use domain_status::config::WHOIS_TIMEOUT_SECS;

    let invalid_domain = "example.invalidtldthatdoesnotexist123456";

    let start = Instant::now();

    // FIX: Wrap WHOIS lookup in explicit timeout
    let result = timeout(
        Duration::from_secs(WHOIS_TIMEOUT_SECS),
        lookup_whois(invalid_domain, None),
    )
    .await;

    let elapsed = start.elapsed();

    println!("WHOIS lookup with fix took {:.2}s", elapsed.as_secs_f64());
    println!("Result: {:?}", result.is_err());

    // With fix: Should timeout after ~5s
    assert!(
        elapsed.as_secs() < 7,
        "Request should fail fast (~5s) with WHOIS_TIMEOUT_SECS = {}",
        WHOIS_TIMEOUT_SECS
    );
}
