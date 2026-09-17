//! Offline gold-set contracts for serving-stack fingerprint quality.

use super::{detect_technologies_blocking, DetectedTechnology};
use crate::fingerprint::models::{FingerprintMetadata, FingerprintRuleset, Technology};
use reqwest::header::{HeaderMap, HeaderValue};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::SystemTime;

fn empty_tech() -> Technology {
    Technology::default()
}

fn meta() -> FingerprintMetadata {
    FingerprintMetadata {
        source: "gold-set".into(),
        version: "0".into(),
        last_updated: SystemTime::now(),
    }
}

fn names(techs: &[DetectedTechnology]) -> HashSet<&str> {
    techs.iter().map(|t| t.name.as_str()).collect()
}

fn detect(
    ruleset: &Arc<FingerprintRuleset>,
    headers: &HeaderMap,
    html: &str,
    url: &str,
    script_sources: &[String],
) -> Vec<DetectedTechnology> {
    detect_technologies_blocking(
        ruleset,
        headers,
        &HashMap::new(),
        script_sources,
        &html.to_lowercase(),
        url,
        &HashSet::new(),
        "",
    )
    .expect("detect")
}

fn server_header(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(reqwest::header::SERVER, value.parse().unwrap());
    headers
}

#[test]
fn github_com_is_not_pages_docusign_or_m365() {
    let mut pages = empty_tech();
    pages
        .headers
        .insert("server".into(), r"^GitHub\.com$".into());
    pages.url.push(r"\.github\.io".into());

    let mut docusign = empty_tech();
    docusign.dns.insert("TXT".into(), vec!["docusign=".into()]);

    let mut m365 = empty_tech();
    m365.dns.insert("MX".into(), vec!["outlook\\.com".into()]);

    let mut react = empty_tech();
    react.html.push("react".into());

    let ruleset = Arc::new(FingerprintRuleset {
        technologies: HashMap::from([
            ("GitHub Pages".into(), pages),
            ("DocuSign".into(), docusign),
            ("Microsoft 365".into(), m365),
            ("React".into(), react),
        ]),
        categories: HashMap::new(),
        metadata: meta(),
    });

    let html = "<html><body>Built with React for developers</body></html>";
    let result = detect(
        &ruleset,
        &server_header("github.com"),
        html,
        "https://github.com/",
        &[],
    );
    let names = names(&result);
    assert!(
        !names.contains("GitHub Pages"),
        "github.com must not be GitHub Pages, got {result:?}"
    );
    assert!(
        !names.contains("DocuSign") && !names.contains("Microsoft 365"),
        "TXT/MX org-proofs must not become techs, got {result:?}"
    );
    assert!(
        names.contains("React"),
        "React HTML marker should still match, got {result:?}"
    );
}

#[test]
fn wordpress_html_detects_wordpress() {
    let mut wp = empty_tech();
    wp.html.push("wp-content".into());
    wp.cats.push(1);
    wp.implies.push("PHP".into());
    let php = empty_tech();
    let ruleset = Arc::new(FingerprintRuleset {
        technologies: HashMap::from([("WordPress".into(), wp), ("PHP".into(), php)]),
        categories: HashMap::from([(1, "CMS".into())]),
        metadata: meta(),
    });
    let html = r#"<link rel="stylesheet" href="/wp-content/themes/twenty-twenty-one/style.css">"#;
    let result = detect(
        &ruleset,
        &HeaderMap::new(),
        html,
        "https://wordpress.org/",
        &[],
    );
    let names = names(&result);
    assert!(names.contains("WordPress"), "got {result:?}");
    assert!(
        result.iter().any(|t| t.name == "PHP" && t.is_implied),
        "PHP should be implied, got {result:?}"
    );
}

#[test]
fn vercel_x_powered_by_next_js() {
    let mut next = empty_tech();
    next.headers
        .insert("x-powered-by".into(), "Next\\.js".into());
    next.implies.push("React".into());
    next.implies.push("Node.js".into());
    let ruleset = Arc::new(FingerprintRuleset {
        technologies: HashMap::from([
            ("Next.js".into(), next),
            ("React".into(), empty_tech()),
            ("Node.js".into(), empty_tech()),
        ]),
        categories: HashMap::new(),
        metadata: meta(),
    });
    let mut headers = HeaderMap::new();
    headers.insert(
        reqwest::header::HeaderName::from_static("x-powered-by"),
        HeaderValue::from_static("Next.js"),
    );
    let result = detect(
        &ruleset,
        &headers,
        "<html></html>",
        "https://vercel.com/",
        &[],
    );
    let names = names(&result);
    assert!(names.contains("Next.js"), "got {result:?}");
    assert!(
        result
            .iter()
            .any(|t| t.name == "Next.js" && t.detection_source.as_deref() == Some("header")),
        "Next.js should be header-sourced, got {result:?}"
    );
}

#[test]
fn payload_x_powered_by_is_detected() {
    let mut payload = empty_tech();
    payload
        .headers
        .insert("x-powered-by".into(), "Payload".into());
    let ruleset = Arc::new(FingerprintRuleset {
        technologies: HashMap::from([("Payload".into(), payload)]),
        categories: HashMap::new(),
        metadata: meta(),
    });
    let mut headers = HeaderMap::new();
    headers.insert(
        reqwest::header::HeaderName::from_static("x-powered-by"),
        HeaderValue::from_static("Next.js, Payload"),
    );
    let result = detect(
        &ruleset,
        &headers,
        "<html></html>",
        "https://vercel.com/",
        &[],
    );
    assert!(
        result.iter().any(|t| t.name == "Payload"),
        "overlay Payload header should match, got {result:?}"
    );
}

#[test]
fn s3_csp_only_is_not_amazon_s3() {
    let mut s3 = empty_tech();
    s3.headers.insert(
        "content-security-policy".into(),
        r"s3[^ ]*\.amazonaws\.com".into(),
    );
    s3.headers.insert("server".into(), "^AmazonS3$".into());
    let ruleset = Arc::new(FingerprintRuleset {
        technologies: HashMap::from([("Amazon S3".into(), s3)]),
        categories: HashMap::new(),
        metadata: meta(),
    });

    let mut csp = HeaderMap::new();
    csp.insert(
        reqwest::header::HeaderName::from_static("content-security-policy"),
        "img-src https://inaturalist-open-data.s3.amazonaws.com"
            .parse()
            .unwrap(),
    );
    let wikipedia = detect(&ruleset, &csp, "", "https://www.wikipedia.org/", &[]);
    assert!(
        wikipedia.iter().all(|t| t.name != "Amazon S3"),
        "CSP allowlists must not insert Amazon S3, got {wikipedia:?}"
    );

    let hosted = detect(
        &ruleset,
        &server_header("AmazonS3"),
        "",
        "https://bucket.s3.amazonaws.com/",
        &[],
    );
    assert!(
        hosted.iter().any(|t| t.name == "Amazon S3"),
        "Server: AmazonS3 should still fingerprint S3 hosting, got {hosted:?}"
    );
}

#[test]
fn overlay_s3_script_src_alone_is_not_hosting() {
    let mut s3 = empty_tech();
    s3.headers.insert("server".into(), "^AmazonS3$".into());
    s3.headers
        .insert("x-amz-server-side-encryption".into(), String::new());
    let ruleset = Arc::new(FingerprintRuleset {
        technologies: HashMap::from([("Amazon S3".into(), s3)]),
        categories: HashMap::new(),
        metadata: meta(),
    });
    let result = detect(
        &ruleset,
        &HeaderMap::new(),
        "",
        "https://github.com/",
        &["https://github-production-user-asset-6210df.s3.amazonaws.com/foo.js".into()],
    );
    assert!(
        result.iter().all(|t| t.name != "Amazon S3"),
        "scriptSrc-only S3 URLs must not count as S3 hosting after overlay, got {result:?}"
    );
}

#[test]
fn lets_encrypt_is_not_a_technology() {
    let mut le = empty_tech();
    le.html.push("let's encrypt".into());
    le.cert_issuer.push("Let's Encrypt".into());
    le.cats.push(70);
    let ruleset = Arc::new(FingerprintRuleset {
        technologies: HashMap::from([("Let's Encrypt".into(), le)]),
        categories: HashMap::from([(70, "SSL/TLS certificate authorities".into())]),
        metadata: meta(),
    });
    let result = detect(
        &ruleset,
        &HeaderMap::new(),
        "<p>Powered by Let's Encrypt</p>",
        "https://example.com/",
        &[],
    );
    assert!(
        result.iter().all(|t| t.name != "Let's Encrypt"),
        "CAs must not land in url_technologies, got {result:?}"
    );
}

#[test]
fn gravity_forms_requires_wordpress() {
    let mut plugin = empty_tech();
    plugin.html.push("gravityforms".into());
    plugin.requires.push("WordPress".into());
    let mut wp = empty_tech();
    wp.html.push("wp-content".into());
    let ruleset = Arc::new(FingerprintRuleset {
        technologies: HashMap::from([("Gravity Forms".into(), plugin), ("WordPress".into(), wp)]),
        categories: HashMap::new(),
        metadata: meta(),
    });
    let orphan = detect(
        &ruleset,
        &HeaderMap::new(),
        "<form class=\"gravityforms\"></form>",
        "https://example.com/",
        &[],
    );
    assert!(
        orphan.iter().all(|t| t.name != "Gravity Forms"),
        "plugin without WordPress must drop, got {orphan:?}"
    );

    let with_wp = detect(
        &ruleset,
        &HeaderMap::new(),
        "<form class=\"gravityforms\"></form><link href=\"/wp-content/x.css\">",
        "https://example.com/",
        &[],
    );
    let names = names(&with_wp);
    assert!(names.contains("Gravity Forms") && names.contains("WordPress"));
}
