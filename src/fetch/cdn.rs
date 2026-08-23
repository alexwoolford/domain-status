//! Passive CDN / edge-provider taxonomy from passive signals.
//!
//! Derives a single best-effort `cdn_provider` label from HTTP headers,
//! CNAME chain, and nameserver hostnames — no extra network I/O.

use std::collections::HashMap;

/// Detect a CDN/edge provider from headers and DNS artifacts.
///
/// Returns a stable lowercase slug (`cloudflare`, `fastly`, `cloudfront`, …)
/// or `None` when no confident signal is present.
pub(crate) fn detect_cdn_provider(
    http_headers: &HashMap<String, String>,
    security_headers: &HashMap<String, String>,
    cname_chain_json: Option<&str>,
    nameservers_json: Option<&str>,
) -> Option<String> {
    if let Some(provider) = detect_from_headers(http_headers).or_else(|| detect_from_headers(security_headers))
    {
        return Some(provider);
    }
    if let Some(provider) = detect_from_dns_blob(cname_chain_json) {
        return Some(provider);
    }
    detect_from_dns_blob(nameservers_json)
}

fn header_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn detect_from_headers(headers: &HashMap<String, String>) -> Option<String> {
    if header_value(headers, "cf-ray").is_some()
        || header_value(headers, "cf-cache-status").is_some()
    {
        return Some("cloudflare".to_string());
    }
    if header_value(headers, "x-served-by")
        .is_some_and(|v| v.to_ascii_lowercase().contains("cache-"))
        || header_value(headers, "fastly-io-info").is_some()
    {
        return Some("fastly".to_string());
    }
    if header_value(headers, "x-amz-cf-id").is_some()
        || header_value(headers, "x-amz-cf-pop").is_some()
    {
        return Some("cloudfront".to_string());
    }
    if header_value(headers, "x-azure-ref").is_some()
        || header_value(headers, "x-msedge-ref").is_some()
    {
        return Some("azure".to_string());
    }
    if header_value(headers, "x-akamai-request-id").is_some()
        || header_value(headers, "akamai-grn").is_some()
    {
        return Some("akamai".to_string());
    }
    if header_value(headers, "x-vercel-id").is_some()
        || header_value(headers, "x-vercel-cache").is_some()
    {
        return Some("vercel".to_string());
    }
    if header_value(headers, "x-nf-request-id").is_some() {
        return Some("netlify".to_string());
    }
    if header_value(headers, "x-github-request-id").is_some() {
        return Some("github_pages".to_string());
    }
    if let Some(server) = header_value(headers, "server") {
        let lower = server.to_ascii_lowercase();
        if lower.contains("cloudflare") {
            return Some("cloudflare".to_string());
        }
        if lower.contains("netlify") {
            return Some("netlify".to_string());
        }
    }
    if let Some(via) = header_value(headers, "via") {
        let lower = via.to_ascii_lowercase();
        if lower.contains("cloudfront") {
            return Some("cloudfront".to_string());
        }
        if lower.contains("varnish") && header_value(headers, "x-served-by").is_some() {
            return Some("fastly".to_string());
        }
    }
    None
}

fn detect_from_dns_blob(json: Option<&str>) -> Option<String> {
    let blob = json?.to_ascii_lowercase();
    const RULES: &[(&str, &str)] = &[
        ("cloudflare", "cloudflare"),
        ("cdn.cloudflare.net", "cloudflare"),
        ("fastly", "fastly"),
        ("fastly.net", "fastly"),
        ("cloudfront.net", "cloudfront"),
        ("akamai", "akamai"),
        ("akamaiedge", "akamai"),
        ("edgekey.net", "akamai"),
        ("azureedge.net", "azure"),
        ("trafficmanager.net", "azure"),
        ("vercel-dns", "vercel"),
        ("vercel.app", "vercel"),
        ("netlify", "netlify"),
        ("github.io", "github_pages"),
        ("googleusercontent", "google"),
        ("ghs.google", "google"),
        ("awsdns", "aws_dns"),
    ];
    for (needle, provider) in RULES {
        if blob.contains(needle) {
            return Some((*provider).to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_cloudflare_from_cf_ray() {
        let mut headers = HashMap::new();
        headers.insert("CF-Ray".to_string(), "abc-SJC".to_string());
        assert_eq!(
            detect_cdn_provider(&headers, &HashMap::new(), None, None).as_deref(),
            Some("cloudflare")
        );
    }

    #[test]
    fn detects_cloudfront_from_cname() {
        let cname = r#"["d111111abcdef8.cloudfront.net."]"#;
        assert_eq!(
            detect_cdn_provider(&HashMap::new(), &HashMap::new(), Some(cname), None).as_deref(),
            Some("cloudfront")
        );
    }

    #[test]
    fn detects_from_nameservers() {
        let ns = r#"["ns1.vercel-dns.com.","ns2.vercel-dns.com."]"#;
        assert_eq!(
            detect_cdn_provider(&HashMap::new(), &HashMap::new(), None, Some(ns)).as_deref(),
            Some("vercel")
        );
    }

    #[test]
    fn returns_none_without_signals() {
        assert!(detect_cdn_provider(&HashMap::new(), &HashMap::new(), None, None).is_none());
    }
}
