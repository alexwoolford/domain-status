// Quick test to understand Next.js detection
// Run with: cargo run --bin investigate_detection

use domain_status::fingerprint::{detect_technologies, init_ruleset};
use reqwest::header::HeaderMap;
use std::collections::{HashMap, HashSet};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize ruleset
    init_ruleset().await?;

    // Test with 10xgenomics.com-like data
    let mut headers = HeaderMap::new();
    headers.insert("x-vercel-id", "sfo1::test".parse().unwrap());
    headers.insert("set-cookie", "CookieYes=test".parse().unwrap());

    let meta_tags = HashMap::new();
    let script_sources = vec![];
    let script_content = "";
    let html_text = "";
    let url = "https://10xgenomics.com";
    let script_tag_ids = HashSet::new(); // No __NEXT_DATA__

    let detected = detect_technologies(
        &meta_tags,
        &script_sources,
        script_content,
        html_text,
        &headers,
        url,
        &script_tag_ids,
    ).await?;

    println!("Detected technologies: {:?}", detected);

    // Check if Next.js is in there
    if detected.contains("Next.js") {
        println!("ERROR: Next.js detected but shouldn't be!");
    } else {
        println!("OK: Next.js not detected (as expected)");
    }

    Ok(())
}
