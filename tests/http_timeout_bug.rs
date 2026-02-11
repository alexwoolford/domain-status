//! Test demonstrating HTTP client timeout bug.
//!
//! **BUG**: The reqwest::Client is configured with only a global timeout,
//! but does NOT set:
//! - connect_timeout() for TCP connection phase
//! - Custom DNS resolver with DNS_TIMEOUT_SECS
//!
//! This means DNS/TCP/TLS operations can hang longer than intended.

use std::time::{Duration, Instant};

/// Demonstrates that HTTP client hangs on slow TCP connect.
///
/// This test uses a "blackhole" IP (TEST-NET-1: 192.0.2.1) that drops packets.
/// A properly configured HTTP client should timeout quickly during TCP connect
/// (config::TCP_CONNECT_TIMEOUT_SECS = 5s), but without .connect_timeout(),
/// it waits for the full global timeout (10s).
#[tokio::test]
#[ignore] // Run with: cargo test --test http_timeout_bug -- --ignored
async fn test_http_client_slow_tcp_connect() {
    // Use non-routable IP - TCP connect will hang/timeout
    let blackhole_ip = "10.255.255.1:80";

    // Create HTTP client using the same configuration as the codebase
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10)) // Global timeout from config
        // BUG: Missing .connect_timeout(Duration::from_secs(5))
        .build()
        .expect("Failed to build client");

    let start = Instant::now();
    let url = format!("http://{}/", blackhole_ip);

    let result = client.get(&url).send().await;

    let elapsed = start.elapsed();

    // Expected: Should timeout after ~5s (TCP_CONNECT_TIMEOUT_SECS)
    // Actual: Times out after 10s (global timeout)
    println!("Request took {:.2}s", elapsed.as_secs_f64());
    println!("Result: {:?}", result.map(|r| r.status()));

    // **BUG EXPOSED**: This assertion should pass if connect_timeout is set
    // but it FAILS because reqwest uses the full 10s global timeout
    assert!(
        elapsed.as_secs() < 7,
        "BUG: HTTP client took {:.2}s instead of failing fast (~5s) during TCP connect",
        elapsed.as_secs_f64()
    );
}

/// Demonstrates the fix: reqwest with connect_timeout.
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
