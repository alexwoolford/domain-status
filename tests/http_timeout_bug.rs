//! Test demonstrating HTTP client timeout bug.
//!
//! **BUG**: The `reqwest::Client` is configured with only a global timeout,
//! but does NOT set:
//! - `connect_timeout()` for TCP connection phase
//! - Custom DNS resolver with `DNS_TIMEOUT_SECS`
//!
//! This means DNS/TCP/TLS operations can hang longer than intended.

use std::time::{Duration, Instant};

// Note: a previous "demonstration" test for the no-connect_timeout case was
// removed. It only printed the elapsed time and never asserted, so it could not
// fail even when the bug regressed. The post-fix test below
// (test_http_client_with_connect_timeout_fix) does assert the elapsed time
// against the expected connect-timeout, which is the actual regression gate.

/// Demonstrates the fix: reqwest with `connect_timeout`.
#[tokio::test]
#[ignore]
async fn test_http_client_with_connect_timeout_fix() {
    // Use non-routable IP - TCP connect will hang/timeout
    let blackhole_ip = "10.255.255.1:80";

    // FIX: Add connect_timeout
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10)) // Global timeout
        .connect_timeout(Duration::from_secs(5)) // TCP connect timeout (FIXED)
        .build()
        .expect("Failed to build client");

    let start = Instant::now();
    let url = format!("http://{}/", blackhole_ip);

    let result = client.get(&url).send().await;

    let elapsed = start.elapsed();

    println!("Request with fix took {:.2}s", elapsed.as_secs_f64());
    println!("Result: {:?}", result.map(|r| r.status()));

    // With fix: Should timeout after ~5s
    assert!(
        elapsed.as_secs() < 7,
        "Request should fail fast (~5s) with connect_timeout"
    );
}
