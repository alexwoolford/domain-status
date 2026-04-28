//! Optional external `<script src="...">` fetching for secret detection.
//!
//! Off by default; enabled by [`crate::config::Config::scan_external_scripts`].
//!
//! When enabled, after the primary HTML body has been parsed, the scanner
//! resolves each `<script src>` URL against the page's final URL,
//! SSRF-validates it, fetches up to [`MAX_SCRIPT_FETCH_PER_PAGE`] scripts in
//! parallel under tight size/timeout caps, decodes each with charset
//! detection, and runs [`crate::parse::detect_exposed_secrets`] over each
//! body. Findings are tagged with a `location` of the form
//! `external_script:<url>` so analysts can see which bundle leaked.
//!
//! Why a separate module: the operation is opt-in and dramatically widens
//! the threat surface (we make GET requests to arbitrary script URLs the
//! page references), so isolating it makes the behaviour easy to audit
//! and to test in isolation.

use std::time::Duration;

use crate::parse::ExposedSecret;
use crate::security::validate_url_safe;

/// Hard cap on how many `<script src>` URLs we attempt to fetch per page.
///
/// Pages can reference dozens of scripts; fetching them all serialises
/// scanning latency and pushes the page-level timing past anything useful.
/// 10 covers the common case (analytics + 1-2 SPA bundles + a handful of
/// tracking scripts) without exploding the per-URL budget.
pub const MAX_SCRIPT_FETCH_PER_PAGE: usize = 10;

/// Per-script body size cap. Far below the 2 MB cap on the primary page
/// because typical bundles fit comfortably; this also limits memory
/// pressure when scanning many pages concurrently.
pub const MAX_SCRIPT_BODY_BYTES: usize = 1024 * 1024;

/// Per-script fetch timeout. Independent of the page's `timeout_seconds`
/// so an unusually slow CDN doesn't blow up the page-level budget.
pub const SCRIPT_FETCH_TIMEOUT_SECS: u64 = 5;

/// Fetches external scripts referenced by a page and returns secrets found
/// in their bodies, each tagged with `location = "external_script:<url>"`.
///
/// Errors during individual fetches are logged at debug and silently
/// skipped — the goal is best-effort coverage, not full-fidelity error
/// reporting.
pub async fn scan_external_scripts(
    client: &reqwest::Client,
    page_url: &str,
    script_sources: &[String],
    allow_localhost: bool,
) -> Vec<ExposedSecret> {
    if script_sources.is_empty() {
        return Vec::new();
    }
    let resolved: Vec<String> = script_sources
        .iter()
        .filter_map(|src| resolve_script_url(page_url, src))
        .filter(|abs| {
            // Only http(s) URLs make sense here; data:, blob:, javascript:
            // can't carry meaningful secrets in this scanner's threat model.
            abs.starts_with("http://") || abs.starts_with("https://")
        })
        .filter(|abs| allow_localhost || validate_url_safe(abs).is_ok())
        .take(MAX_SCRIPT_FETCH_PER_PAGE)
        .collect();

    if resolved.is_empty() {
        return Vec::new();
    }

    log::debug!(
        "scan_external_scripts: page={} candidates={} fetching",
        page_url,
        resolved.len()
    );

    // Fetch all candidates concurrently. Per-script timeout caps each one;
    // join_all lets us collect whatever returns within those caps.
    let fetches = resolved.iter().map(|url| async move {
        let body_opt = fetch_script_body(client, url).await;
        body_opt.map(|body| (url.clone(), body))
    });
    let results = futures::future::join_all(fetches).await;

    let mut all_secrets: Vec<ExposedSecret> = Vec::new();
    for fetched in results.into_iter().flatten() {
        let (url, body) = fetched;
        let mut found = crate::parse::detect_exposed_secrets(&body);
        if found.is_empty() {
            continue;
        }
        let location: std::borrow::Cow<'static, str> =
            std::borrow::Cow::Owned(format!("external_script:{url}"));
        for secret in &mut found {
            secret.location = location.clone();
        }
        all_secrets.extend(found);
    }

    all_secrets
}

/// Resolves a `<script src>` value against the page's final URL.
///
/// Handles absolute URLs, protocol-relative (`//cdn.example.com/...`), and
/// path-relative (`/static/main.js`, `assets/foo.js`). Returns `None` if
/// resolution fails (e.g. a malformed `src`).
fn resolve_script_url(page_url: &str, src: &str) -> Option<String> {
    let trimmed = src.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(abs) = url::Url::parse(trimmed) {
        return Some(abs.to_string());
    }
    let base = url::Url::parse(page_url).ok()?;
    base.join(trimmed).ok().map(|u| u.to_string())
}

/// Fetches a script body with size + timeout caps and charset-aware decoding.
async fn fetch_script_body(client: &reqwest::Client, url: &str) -> Option<String> {
    let resp = match tokio::time::timeout(
        Duration::from_secs(SCRIPT_FETCH_TIMEOUT_SECS),
        client.get(url).send(),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            log::debug!("external_script: fetch error for {url}: {e}");
            return None;
        }
        Err(_) => {
            log::debug!("external_script: fetch timed out for {url}");
            return None;
        }
    };

    if !resp.status().is_success() {
        log::debug!(
            "external_script: non-success status {} for {url}",
            resp.status()
        );
        return None;
    }

    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(std::string::ToString::to_string);

    // Stream the body up to MAX_SCRIPT_BODY_BYTES.
    let mut accumulated: Vec<u8> = Vec::new();
    use futures::StreamExt;
    let mut stream = resp.bytes_stream();
    while let Some(chunk_result) = stream.next().await {
        let chunk = match chunk_result {
            Ok(c) => c,
            Err(e) => {
                log::debug!("external_script: chunk error for {url}: {e}");
                return None;
            }
        };
        if accumulated.len() + chunk.len() > MAX_SCRIPT_BODY_BYTES {
            log::debug!("external_script: aborting {url} at size cap");
            return None;
        }
        accumulated.extend_from_slice(&chunk);
    }

    Some(decode_script_body(&accumulated, content_type.as_deref()))
}

/// Charset-aware decode for script bodies. Mirrors the page-body decoder so
/// non-UTF-8 scripts (`Shift_JIS`, Windows-1252, etc.) don't get corrupted
/// before regex sees them.
fn decode_script_body(bytes: &[u8], content_type: Option<&str>) -> String {
    use encoding_rs::{Encoding, UTF_8};
    if let Some(ct) = content_type {
        if let Some(label) = charset_from_content_type(ct) {
            if let Some(enc) = Encoding::for_label(label.as_bytes()) {
                let (cow, _, _) = enc.decode(bytes);
                return cow.into_owned();
            }
        }
    }
    if let Some(enc) = Encoding::for_bom(bytes).map(|(e, _bom_len)| e) {
        let (cow, _, _) = enc.decode(bytes);
        return cow.into_owned();
    }
    let (cow, _, _) = UTF_8.decode(bytes);
    cow.into_owned()
}

/// Local copy of the Content-Type charset parser. Kept private so the public
/// API surface doesn't grow; we only need it here and inside
/// `fetch::response::extract`.
fn charset_from_content_type(ct: &str) -> Option<String> {
    for part in ct.split(';').map(str::trim) {
        if let Some(rest) = part.strip_prefix("charset=").or_else(|| {
            if part.len() >= 8 && part[..8].eq_ignore_ascii_case("charset=") {
                Some(&part[8..])
            } else {
                None
            }
        }) {
            let trimmed = rest.trim().trim_matches(|c: char| c == '"' || c == '\'');
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use httptest::{matchers::*, responders::*, Expectation, Server};

    #[test]
    fn test_resolve_script_url_absolute() {
        let resolved =
            resolve_script_url("https://example.com/page", "https://cdn.example.org/x.js");
        assert_eq!(resolved.as_deref(), Some("https://cdn.example.org/x.js"));
    }

    #[test]
    fn test_resolve_script_url_protocol_relative() {
        let resolved = resolve_script_url("https://example.com/page", "//cdn.example.org/x.js");
        assert_eq!(resolved.as_deref(), Some("https://cdn.example.org/x.js"));
    }

    #[test]
    fn test_resolve_script_url_path_relative() {
        let resolved = resolve_script_url("https://example.com/dir/page.html", "static/main.js");
        assert_eq!(
            resolved.as_deref(),
            Some("https://example.com/dir/static/main.js")
        );
    }

    #[test]
    fn test_resolve_script_url_root_relative() {
        let resolved = resolve_script_url("https://example.com/page", "/assets/main.js");
        assert_eq!(
            resolved.as_deref(),
            Some("https://example.com/assets/main.js")
        );
    }

    #[test]
    fn test_resolve_script_url_empty_returns_none() {
        assert!(resolve_script_url("https://example.com/", "").is_none());
        assert!(resolve_script_url("https://example.com/", "   ").is_none());
    }

    #[test]
    fn test_decode_script_body_uses_charset() {
        let bytes = b"\x93secret\x94";
        let decoded =
            decode_script_body(bytes, Some("application/javascript; charset=windows-1252"));
        assert!(decoded.contains('\u{201C}'));
        assert!(!decoded.contains('\u{FFFD}'));
    }

    #[tokio::test]
    async fn test_scan_external_scripts_finds_secret_and_tags_location() {
        let server = Server::run();
        // Build an AWS-shaped key at runtime to avoid GitHub push protection
        // matching it in the source. Format: AKIA + 16 chars from [A-Z2-7].
        // 16-char suffix here yields a full 20-char access-key-id.
        let aws_key = format!("AKIA{}", "IOSFODNN7EXAMPL2");
        let body_template = "var aws = '__AWS__';";
        let bound_body = body_template.replace("__AWS__", &aws_key);
        server.expect(
            Expectation::matching(request::method_path("GET", "/main.js")).respond_with(
                status_code(200)
                    .insert_header("Content-Type", "application/javascript; charset=utf-8")
                    .body(bound_body),
            ),
        );

        let client = reqwest::Client::new();
        let server_url = server.url("/main.js").to_string();
        // SSRF check rejects loopback by default; bypass for this test.
        let secrets = scan_external_scripts(
            &client,
            "https://example.com/page", // page URL
            std::slice::from_ref(&server_url),
            true, // allow_localhost
        )
        .await;

        let found = secrets
            .iter()
            .find(|s| s.secret_type == "aws-access-token")
            .unwrap_or_else(|| panic!("expected aws-access-token; got {secrets:?}"));
        assert_eq!(found.matched_value, aws_key);
        assert!(
            found.location.starts_with("external_script:"),
            "location should be tagged external_script:..., got {:?}",
            found.location
        );
        assert!(found.location.contains(&server_url));
    }

    #[tokio::test]
    async fn test_scan_external_scripts_skips_loopback_when_disallowed() {
        let server = Server::run();
        // Server expects no requests since SSRF should reject before fetching.
        let client = reqwest::Client::new();
        let server_url = server.url("/main.js").to_string();
        let secrets = scan_external_scripts(
            &client,
            "https://example.com/page",
            &[server_url],
            false, // allow_localhost = false (production)
        )
        .await;
        assert!(secrets.is_empty());
    }

    #[tokio::test]
    async fn test_scan_external_scripts_caps_at_max_per_page() {
        // Build MAX+5 candidate URLs but only register handlers for the first MAX.
        let server = Server::run();
        let mut urls = Vec::new();
        for i in 0..(MAX_SCRIPT_FETCH_PER_PAGE + 5) {
            let path = format!("/s{i}.js");
            urls.push(server.url(&path).to_string());
            // Allow 0..MAX_SCRIPT_FETCH_PER_PAGE handlers; expect_any tolerates extras.
            if i < MAX_SCRIPT_FETCH_PER_PAGE {
                server.expect(
                    Expectation::matching(request::method_path("GET", path))
                        .times(0..=1)
                        .respond_with(status_code(200).body("// no secrets")),
                );
            }
        }
        let client = reqwest::Client::new();
        let _ = scan_external_scripts(&client, "https://example.com/page", &urls, true).await;
        // No assertion on `secrets` beyond emptiness; the cap is verified by
        // observing the test doesn't panic on the unmocked /s10..s14 paths.
    }
}
