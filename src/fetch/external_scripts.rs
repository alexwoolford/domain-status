//! Optional external `<script src="...">` fetching for secret detection and
//! static technology fingerprinting (`scripts` patterns).
//!
//! Off by default; enabled by [`crate::config::Config::scan_external_scripts`].
//!
//! When enabled, after the primary HTML body has been parsed, the scanner
//! resolves each `<script src>` URL against the page's final URL, keeps only
//! **first-party** bundles (same registrable domain / eTLD+1 as the page,
//! minus a denylist of known third-party CDN hosts), SSRF-validates them,
//! fetches up to [`MAX_SCRIPT_FETCH_PER_PAGE`] scripts in parallel under tight
//! size/timeout caps, decodes each with charset detection, and:
//! - runs [`crate::parse::detect_exposed_secrets`] over each body on
//!   `spawn_blocking` (findings tagged `external_script:<url>`)
//! - concatenates lowercase bodies for Wappalyzer `scripts` pattern matching
//!
//! Third-party CDNs (Stripe.js, Cookiebot, Google Analytics, etc.) are skipped
//! because they dominate false positives while almost never containing the
//! site's own credentials. Real leaks show up in first-party SPA bundles.
//!
//! Why a separate module: the operation is opt-in and dramatically widens
//! the threat surface (we make GET requests to script URLs the page
//! references), so isolating it makes the behaviour easy to audit and to
//! test in isolation.

use std::time::Duration;

use crate::parse::ExposedSecret;
use crate::security::validate_url_safe;

/// Hard cap on how many `<script src>` URLs we attempt to fetch per page.
///
/// Pages can reference dozens of scripts; fetching them all serialises
/// scanning latency and pushes the page-level timing past anything useful.
/// 10 covers the common case (1-2 SPA bundles + a handful of first-party
/// helpers) without exploding the per-URL budget.
pub const MAX_SCRIPT_FETCH_PER_PAGE: usize = 10;

/// Per-script body size cap. Far below the 2 MB cap on the primary page
/// because typical bundles fit comfortably; this also limits memory
/// pressure when scanning many pages concurrently.
pub const MAX_SCRIPT_BODY_BYTES: usize = 1024 * 1024;

/// Per-script fetch timeout. Independent of the page's `timeout_seconds`
/// so an unusually slow CDN doesn't blow up the page-level budget.
pub const SCRIPT_FETCH_TIMEOUT_SECS: u64 = 5;

/// Host suffixes (and exact hosts) that are never treated as first-party,
/// even when somehow served under a matching eTLD+1 via a reverse proxy.
const KNOWN_THIRD_PARTY_SCRIPT_HOST_SUFFIXES: &[&str] = &[
    "js.stripe.com",
    "consent.cookiebot.com",
    "assets.squarespace.com",
    "www.google-analytics.com",
    "www.googletagmanager.com",
    "connect.facebook.net",
    "maps.googleapis.com",
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "ajax.googleapis.com",
    "fast.wistia.com",
    "hcaptcha.com",
    "www.google.com",
    "imasdk.googleapis.com",
    "static.cloudflareinsights.com",
    "cdn.weglot.com",
];

/// Result of an optional external-script scan, including coverage counts.
#[derive(Debug, Default)]
pub struct ExternalScriptScanResult {
    pub secrets: Vec<ExposedSecret>,
    /// First-party `<script src>` candidates after filtering (before per-page cap).
    pub eligible: u32,
    /// Scripts successfully fetched and scanned (may be less than eligible due to cap/errors).
    pub scanned: u32,
    /// Lowercase concatenation of successfully fetched bodies (for `scripts` tech patterns).
    pub script_bodies_text: String,
}

/// Fetches external scripts referenced by a page and returns secrets found
/// in their bodies (tagged `external_script:<url>`) plus concatenated body
/// text for static technology fingerprinting.
///
/// Only first-party scripts (same registrable domain as `page_url`) are
/// fetched. Errors during individual fetches are logged at debug and
/// silently skipped — the goal is best-effort coverage, not full-fidelity
/// error reporting.
pub async fn scan_external_scripts(
    client: &reqwest::Client,
    page_url: &str,
    script_sources: &[String],
    allow_localhost: bool,
) -> ExternalScriptScanResult {
    if script_sources.is_empty() {
        return ExternalScriptScanResult::default();
    }
    let eligible: Vec<String> = script_sources
        .iter()
        .filter_map(|src| resolve_script_url(page_url, src))
        .filter(|abs| abs.starts_with("http://") || abs.starts_with("https://"))
        .filter(|abs| allow_localhost || validate_url_safe(abs).is_ok())
        .filter(|abs| is_first_party_script(page_url, abs))
        .collect();

    let eligible_count = u32::try_from(eligible.len()).unwrap_or(u32::MAX);
    let resolved: Vec<String> = eligible
        .into_iter()
        .take(MAX_SCRIPT_FETCH_PER_PAGE)
        .collect();

    if resolved.is_empty() {
        return ExternalScriptScanResult {
            secrets: Vec::new(),
            eligible: eligible_count,
            scanned: 0,
            script_bodies_text: String::new(),
        };
    }

    log::debug!(
        "scan_external_scripts: page={} eligible={} fetching={}",
        page_url,
        eligible_count,
        resolved.len()
    );

    let fetches = resolved.iter().map(|url| async move {
        let body_opt = fetch_script_body(client, url).await;
        body_opt.map(|body| (url.clone(), body))
    });
    let results = futures::future::join_all(fetches).await;

    // Own fetched bodies, then run CPU-bound secret regex work on the blocking
    // pool (same posture as HTML `parse_html_content` / tech detection).
    let owned: Vec<(String, String)> = results.into_iter().flatten().collect();
    let scanned = u32::try_from(owned.len()).unwrap_or(u32::MAX);

    let (all_secrets, script_bodies_text) = tokio::task::spawn_blocking(move || {
        let mut all_secrets: Vec<ExposedSecret> = Vec::new();
        let mut body_parts: Vec<String> = Vec::new();
        for (url, body) in owned {
            if !body.is_empty() {
                body_parts.push(body.to_lowercase());
            }
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
        (all_secrets, body_parts.join("\n"))
    })
    .await
    .unwrap_or_else(|e| {
        log::warn!("External-script secret scan join failed: {e}");
        (Vec::new(), String::new())
    });

    ExternalScriptScanResult {
        secrets: all_secrets,
        eligible: eligible_count,
        scanned,
        script_bodies_text,
    }
}

/// Returns true when `script_url` is a first-party bundle of `page_url`.
///
/// Same PSL registrable domain (eTLD+1), and not on the known third-party
/// CDN denylist. Relative same-origin scripts always pass.
fn is_first_party_script(page_url: &str, script_url: &str) -> bool {
    let Some(page_host) = url_host(page_url) else {
        return false;
    };
    let Some(script_host) = url_host(script_url) else {
        return false;
    };

    if is_known_third_party_script_host(&script_host) {
        return false;
    }

    // Exact host match covers loopback IPs (tests) and same-host absolute URLs.
    if page_host == script_host {
        return true;
    }

    let Some(page_root) = registrable_domain(&page_host) else {
        return false;
    };
    let Some(script_root) = registrable_domain(&script_host) else {
        return false;
    };
    page_root.eq_ignore_ascii_case(&script_root)
}

fn url_host(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_lowercase))
}

fn registrable_domain(host: &str) -> Option<String> {
    psl::domain_str(host)
        .map(std::string::ToString::to_string)
        .or_else(|| {
            if psl::suffix_str(host).is_some() {
                Some(host.to_string())
            } else {
                None
            }
        })
}

fn is_known_third_party_script_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    KNOWN_THIRD_PARTY_SCRIPT_HOST_SUFFIXES.iter().any(|suffix| {
        host == *suffix
            || host
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
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

/// Unique hosts referenced by `<script src>` on a page, with first-party classification.
///
/// Relative `src` values are resolved against `page_url`. Duplicate hosts are collapsed.
pub(crate) fn collect_script_hosts(
    page_url: &str,
    script_sources: &[String],
) -> Vec<crate::storage::ScriptHostInfo> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for src in script_sources {
        let Some(abs) = resolve_script_url(page_url, src) else {
            continue;
        };
        let Some(host) = url_host(&abs) else {
            continue;
        };
        if !seen.insert(host.clone()) {
            continue;
        }
        let registrable = registrable_domain(&host);
        let is_first_party = is_first_party_script(page_url, &abs);
        out.push(crate::storage::ScriptHostInfo {
            host,
            registrable_domain: registrable,
            is_first_party,
        });
    }
    out
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

    // Stream the body up to MAX_SCRIPT_BODY_BYTES. Oversized bundles are
    // truncated to the cap and the prefix is still scanned — production JS
    // bundles routinely exceed 1MB, and a secret in the first megabyte would
    // otherwise never be seen.
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
            log::debug!("external_script: truncating {url} at size cap");
            let room = MAX_SCRIPT_BODY_BYTES - accumulated.len();
            accumulated.extend_from_slice(&chunk[..room]);
            break;
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

    #[test]
    fn test_is_first_party_script_same_etld() {
        assert!(is_first_party_script(
            "https://www.example.com/page",
            "https://static.example.com/app.js"
        ));
        assert!(is_first_party_script(
            "https://example.co.uk/page",
            "https://cdn.example.co.uk/main.js"
        ));
    }

    #[test]
    fn test_collect_script_hosts_first_and_third_party() {
        let hosts = collect_script_hosts(
            "https://www.example.com/page",
            &[
                "/app.js".to_string(),
                "https://www.googletagmanager.com/gtm.js".to_string(),
                "https://static.example.com/bundle.js".to_string(),
                "/app.js".to_string(),
            ],
        );
        assert!(
            hosts
                .iter()
                .any(|h| h.host == "www.example.com" && h.is_first_party),
            "relative first-party host; got {hosts:?}"
        );
        assert!(
            hosts
                .iter()
                .any(|h| h.host == "static.example.com" && h.is_first_party),
            "same eTLD+1; got {hosts:?}"
        );
        assert!(
            hosts
                .iter()
                .any(|h| h.host == "www.googletagmanager.com" && !h.is_first_party),
            "GTM must be third-party; got {hosts:?}"
        );
        assert_eq!(
            hosts.iter().filter(|h| h.host == "www.example.com").count(),
            1,
            "duplicate hosts collapsed"
        );
    }

    #[test]
    fn test_is_first_party_script_rejects_third_party() {
        assert!(!is_first_party_script(
            "https://www.example.com/page",
            "https://js.stripe.com/v3/"
        ));
        assert!(!is_first_party_script(
            "https://www.example.com/page",
            "https://consent.cookiebot.com/uc.js"
        ));
        assert!(!is_first_party_script(
            "https://www.example.com/page",
            "https://cdn.other.com/lib.js"
        ));
    }

    #[test]
    fn test_is_first_party_script_rejects_cdn_even_on_matching_suffix() {
        // Belt-and-suspenders: denylisted hosts never count as first-party.
        assert!(!is_first_party_script(
            "https://stripe.com/docs",
            "https://js.stripe.com/v3/"
        ));
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
        // Page URL must share the httptest host so first-party filtering allows it.
        let page_url = server.url("/page").to_string();
        // SSRF check rejects loopback by default; bypass for this test.
        let result = scan_external_scripts(
            &client,
            &page_url,
            std::slice::from_ref(&server_url),
            true, // allow_localhost
        )
        .await;

        let found = result
            .secrets
            .iter()
            .find(|s| s.secret_type == "aws-access-token")
            .unwrap_or_else(|| panic!("expected aws-access-token; got {:?}", result.secrets));
        assert_eq!(found.matched_value, aws_key);
        assert!(
            found.location.starts_with("external_script:"),
            "location should be tagged external_script:..., got {:?}",
            found.location
        );
        assert!(found.location.contains(&server_url));
        assert_eq!(result.eligible, 1);
        assert_eq!(result.scanned, 1);
        assert!(
            result.script_bodies_text.contains("var aws"),
            "fetched body text must be retained for tech fingerprints; got {:?}",
            result.script_bodies_text
        );
    }

    #[tokio::test]
    async fn test_scan_external_scripts_retains_body_without_secrets() {
        let server = Server::run();
        let marker = "function webpackJsonpCallback(data) { return data; }";
        server.expect(
            Expectation::matching(request::method_path("GET", "/app.js")).respond_with(
                status_code(200)
                    .insert_header("Content-Type", "application/javascript")
                    .body(marker),
            ),
        );

        let client = reqwest::Client::new();
        let server_url = server.url("/app.js").to_string();
        let page_url = server.url("/page").to_string();
        let result =
            scan_external_scripts(&client, &page_url, std::slice::from_ref(&server_url), true)
                .await;

        assert!(result.secrets.is_empty());
        assert_eq!(result.scanned, 1);
        assert!(
            result
                .script_bodies_text
                .contains("function webpackjsonpcallback"),
            "lowercase body haystack expected; got {:?}",
            result.script_bodies_text
        );
    }

    #[tokio::test]
    async fn test_scan_external_scripts_skips_third_party_cdn() {
        let client = reqwest::Client::new();
        let result = scan_external_scripts(
            &client,
            "https://example.com/page",
            &["https://js.stripe.com/v3/".to_string()],
            false,
        )
        .await;
        assert!(
            result.secrets.is_empty(),
            "third-party CDN scripts must not be fetched"
        );
        assert_eq!(result.eligible, 0);
        assert_eq!(result.scanned, 0);
    }

    #[tokio::test]
    async fn test_scan_external_scripts_skips_loopback_when_disallowed() {
        let server = Server::run();
        // Server expects no requests since SSRF should reject before fetching.
        let client = reqwest::Client::new();
        let server_url = server.url("/main.js").to_string();
        let page_url = server.url("/page").to_string();
        let result = scan_external_scripts(
            &client,
            &page_url,
            &[server_url],
            false, // allow_localhost = false (production)
        )
        .await;
        assert!(result.secrets.is_empty());
        assert_eq!(result.eligible, 0);
    }

    #[tokio::test]
    async fn test_scan_external_scripts_caps_at_max_per_page() {
        // Build MAX+5 candidate URLs but only register handlers for the first MAX.
        let server = Server::run();
        let page_url = server.url("/page").to_string();
        let mut urls = Vec::new();
        for i in 0..(MAX_SCRIPT_FETCH_PER_PAGE + 5) {
            let path = format!("/s{i}.js");
            urls.push(server.url(&path).to_string());
            // Allow 0..MAX_SCRIPT_FETCH_PER_PAGE handlers; expect_any tolerates extras.
            if i < MAX_SCRIPT_FETCH_PER_PAGE {
                server.expect(
                    Expectation::matching(request::method_path("GET", path))
                        .times(1)
                        .respond_with(status_code(200).body("// no secrets")),
                );
            }
        }
        let client = reqwest::Client::new();
        let result = scan_external_scripts(&client, &page_url, &urls, true).await;
        assert_eq!(
            result.eligible as usize,
            MAX_SCRIPT_FETCH_PER_PAGE + 5,
            "eligible counts all first-party candidates before the cap"
        );
        assert_eq!(
            result.scanned as usize, MAX_SCRIPT_FETCH_PER_PAGE,
            "scanned must equal per-page cap; got {}",
            result.scanned
        );
    }
}
