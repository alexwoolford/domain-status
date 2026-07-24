//! FP/FN regression corpus for secret detection.
//!
//! Two directions, both driven off small fixtures:
//!
//! * **FN corpus** — one realistic (synthetic) secret per major rule family,
//!   embedded in the awkward web contexts that used to defeat detection:
//!   next to `debug:false`, inside a URL with a trailing `&`, inside a
//!   newline-free minified document containing a benign allowlist token, and
//!   in a `Set-Cookie` header. Every entry MUST be detected.
//! * **FP corpus** — benign markup that must yield ZERO detections: Cloudflare
//!   email-protection widgets, `wp-content` asset URLs with 40-hex hashes,
//!   HubSpot/LinkedIn embed markup, plain UUIDs, SRI integrity hashes, and
//!   documented placeholder/example keys.
//!
//! Secret literals are assembled at runtime from fragments so the repo's own
//! gitleaks pre-commit hook and CI scan don't fire on this source file. The
//! `tests/` path is additionally allowlisted in `.gitleaks.toml`, but this file
//! lives under `src/`, hence the fragment approach.

use super::{detect_exposed_secrets, detect_exposed_secrets_in_headers};

/// A synthetic JWT (header.payload.signature) assembled at runtime.
fn sample_jwt() -> String {
    [
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0",
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    ]
    .join(".")
}

/// Returns true if any detected secret carries the given rule id.
fn has_rule(body: &str, rule_id: &str) -> bool {
    detect_exposed_secrets(body)
        .iter()
        .any(|s| s.secret_type == rule_id)
}

// ---------------------------------------------------------------------------
// FN corpus: every fixture MUST produce the expected detection.
// ---------------------------------------------------------------------------

#[test]
fn fn_corpus_gcp_key_in_maps_url_with_trailing_amp() {
    // GCP key in a Google Maps script URL, followed by `&` (the canonical
    // public exposure). Regressions in the trailing-boundary relaxation break this.
    let key = "AIza".to_string() + "SyA1234567890abcdefghijklmnopqrstuv";
    let body = format!(
        r#"<script src="https://maps.googleapis.com/maps/api/js?key={key}&libraries=places"></script>"#
    );
    assert!(has_rule(&body, "gcp-api-key"), "missed GCP key in {body}");
}

#[test]
fn fn_corpus_aws_key_next_to_boolean() {
    // AWS key adjacent to `debug:false` — the global-allowlist context bug.
    let key = "AKIA".to_string() + "IOSFODNN7EXAMPL2";
    let body = format!(r#"<script>var c={{apiKey:"{key}",debug:false}};</script>"#);
    assert!(
        has_rule(&body, "aws-access-token"),
        "missed AWS key in {body}"
    );
}

#[test]
fn fn_corpus_secret_in_minified_doc_with_allowlist_token() {
    // Newline-free doc containing a benign `data-cfemail=` widget far from a
    // real AWS key. The line-window cap must keep the allowlist token from
    // suppressing the key.
    let key = "AKIA".to_string() + "IOSFODNN7EXAMPL2";
    let body = format!(
        r#"<span data-cfemail="a1b2c3"></span>{}<script>var k="{key}";</script>"#,
        " ".repeat(2000)
    );
    assert!(!body.contains('\n'), "fixture must be minified");
    assert!(
        has_rule(&body, "aws-access-token"),
        "minified allowlist token suppressed the key"
    );
}

#[test]
fn fn_corpus_jwt_in_json_value() {
    // JWT as a quoted JSON string value (trailing `"` is a valid boundary).
    let body = format!(r#"{{"token":"{}","expired":false}}"#, sample_jwt());
    assert!(has_rule(&body, "jwt"), "missed JWT in JSON value");
}

#[test]
fn fn_corpus_jwt_in_set_cookie_header() {
    // JWT exposed only in a Set-Cookie response header.
    let header_block = format!(
        "Content-Type: text/html\nSet-Cookie: session={}; Path=/; HttpOnly\n",
        sample_jwt()
    );
    let secrets = detect_exposed_secrets_in_headers(&header_block);
    assert!(
        secrets.iter().any(|s| s.secret_type == "jwt"),
        "missed JWT in Set-Cookie; got {secrets:?}"
    );
    assert!(
        secrets.iter().all(|s| s.location == "set_cookie"),
        "header findings must be tagged set_cookie"
    );
}

#[test]
fn fn_corpus_private_key_block() {
    // PEM private-key header is a distinctive, high-signal marker. The gitleaks
    // rule requires 64+ chars of key material between the BEGIN/END markers.
    let body = "-----BEGIN RSA PRIVATE KEY-----\n\
                MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKj\n\
                MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu\n\
                -----END RSA PRIVATE KEY-----";
    assert!(
        !detect_exposed_secrets(body).is_empty(),
        "missed PEM private key block"
    );
}

// ---------------------------------------------------------------------------
// FP corpus: every fixture MUST produce ZERO detections.
// ---------------------------------------------------------------------------

/// Asserts a benign fixture produces no findings, with a helpful message.
fn assert_no_secrets(label: &str, body: &str) {
    let secrets = detect_exposed_secrets(body);
    assert!(
        secrets.is_empty(),
        "{label} must yield zero detections; got {secrets:?}"
    );
}

#[test]
fn fp_corpus_cloudflare_email_protection() {
    assert_no_secrets(
        "cloudflare email-protection widget",
        r#"<a href="/cdn-cgi/l/email-protection#a1b2c3d4e5f6" data-cfemail="a1b2c3d4e5f6">[email&#160;protected]</a>"#,
    );
}

#[test]
fn fp_corpus_wp_content_asset_hash() {
    assert_no_secrets(
        "wp-content asset URL with 40-hex cache buster",
        r#"<img src="/wp-content/uploads/2024/01/a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4.jpg?ver=a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4">"#,
    );
}

#[test]
fn fp_corpus_plain_uuid() {
    assert_no_secrets(
        "bare UUID identifier",
        r#"<div data-id="550e8400-e29b-41d4-a716-446655440000"></div>"#,
    );
}

#[test]
fn fp_corpus_sri_integrity_hash() {
    assert_no_secrets(
        "subresource integrity hash",
        r#"<script src="https://cdn.example.com/lib.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous"></script>"#,
    );
}

#[test]
fn fp_corpus_placeholder_key() {
    assert_no_secrets(
        "documented placeholder API key",
        r#"<code>const apiKey = "YOUR_API_KEY_HERE";</code>"#,
    );
}

#[test]
fn fp_corpus_aws_example_key() {
    // The canonical AWS documentation key must stay allowlisted.
    assert_no_secrets(
        "AWS docs example key",
        r#"<pre>AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE</pre>"#,
    );
}

// ---------------------------------------------------------------------------
// FP corpus additions from live scan.db triage (2026-07).
// ---------------------------------------------------------------------------

#[test]
fn fp_corpus_generic_js_expression_noise() {
    // Cookiebot / consent managers: `key` keyword near `tabIndex=-1`.
    assert_no_secrets(
        "Cookiebot iframe.tabIndex=-1",
        r#"iframe.classList.add(HIDDEN_IFRAME_CLASS),iframe.name="__uspapiLocator",iframe.tabIndex=-1,iframe.setAttribute("role","presentation")"#,
    );
    assert_no_secrets(
        "JS keyContents===0 expression",
        r#"else if(this.keyContents||this.keyContents===0){var n=i.defaults({create:this.options.createModels},e);"#,
    );
}

#[test]
fn fp_corpus_sanity_cms_key() {
    assert_no_secrets(
        "Sanity Portable Text _key",
        r#"{"_key":"7de3cf854a21","_type":"span","marks":[],"text":"Hello"}"#,
    );
}

#[test]
fn fp_corpus_sourcegraph_bare_hex() {
    // Bare 40-hex must not match even when "sourcegraph" appears nearby.
    let hex40 = "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4";
    let body =
        format!(r#"<!-- powered by sourcegraph --><img src="/assets/{hex40}.png" alt="logo">"#);
    assert_no_secrets("sourcegraph keyword + bare 40-hex asset hash", &body);
}

#[test]
fn fp_corpus_jsencrypt_private_key_template() {
    assert_no_secrets(
        "jsencrypt PEM template",
        r#"RSAKey.prototype.getPrivateKey = function () { var a = "-----BEGIN RSA PRIVATE KEY-----\n"; return a += this.wordwrap(this.getPrivateBaseKeyB64()) + "\n", a += "-----END RSA PRIVATE KEY-----"; };"#,
    );
}

#[test]
fn fp_corpus_angular_basic_auth_docs() {
    assert_no_secrets(
        "Angular $http Basic auth docs example",
        r#"*   $http.defaults.headers.common.Authorization = 'Basic YmVlcDpib29w';"#,
    );
}

#[test]
fn fp_corpus_vault_camelcase_css_token() {
    assert_no_secrets(
        "vault s. camelCase design token",
        r#"var h=(0,c.css)({fontWeight:s.typographyH300FontWeight})"#,
    );
}

#[test]
fn fp_corpus_db_uri_template_literal() {
    assert_no_secrets(
        "postgresql template-literal builder",
        r#"let s=`postgresql://${i(r.user)}:${i(r.password)}@${i(r.host)}/${o(r.database)}`,a="string"==typeof e?e:e.text;"#,
    );
}

// ---------------------------------------------------------------------------
// TP corpus: high-value secrets that must still detect.
// ---------------------------------------------------------------------------

#[test]
fn tp_corpus_sendgrid_api_token() {
    // Assembled at runtime so gitleaks pre-commit doesn't fire on this file.
    let token = format!(
        "SG.{}.{}",
        "kxaZ6NLtSdCFrGqIjmrnJA", "AcUYJCeiEC1ritC8rfveYuYXGqXJNcRKzJ4367EHzs4"
    );
    let body = format!(r#"{{"sendgrid_api_key":"{token}"}}"#);
    assert!(
        has_rule(&body, "sendgrid-api-token"),
        "missed SendGrid token"
    );
}

#[test]
fn tp_corpus_shopify_access_token() {
    let token = format!("shpat_{}", "a0f50aa071076dce967553e8e5073b81");
    let body = format!(r#"{{"password":"{token}"}}"#);
    assert!(
        has_rule(&body, "shopify-access-token"),
        "missed Shopify shpat_ token"
    );
}

#[test]
fn tp_corpus_sourcegraph_sgp_prefix_still_detects() {
    // Real Sourcegraph tokens use the sgp_ prefix; must still match.
    let token = format!(
        "sgp_{}_{}",
        "0123456789abcdef", "0123456789abcdef0123456789abcdef01234567"
    );
    let body = format!(r#"const SOURCEGRAPH_TOKEN = "{token}";"#);
    assert!(
        has_rule(&body, "sourcegraph-access-token"),
        "missed sgp_ Sourcegraph token"
    );
}

#[test]
fn tp_corpus_gcp_key_severity_is_low() {
    let key = "AIza".to_string() + "SyA1234567890abcdefghijklmnopqrstuv";
    let body = format!(
        r#"<script src="https://maps.googleapis.com/maps/api/js?key={key}&libraries=places"></script>"#
    );
    let secrets = detect_exposed_secrets(&body);
    let gcp = secrets
        .iter()
        .find(|s| s.secret_type == "gcp-api-key")
        .expect("GCP key must still be detected");
    assert_eq!(
        gcp.severity.as_str(),
        "low",
        "Maps/Firebase client keys are public-by-design"
    );
}

#[test]
fn tp_corpus_opaque_generic_api_key_still_detects() {
    // High-entropy opaque hex assigned to apiKey should still fire generic-api-key.
    let value = "a7f3c9e2b81d4056f9e4a1c8b7d60352e1f90a4b";
    let body = format!(r#"const config = {{ apiKey: "{value}" }};"#);
    assert!(
        has_rule(&body, "generic-api-key"),
        "plausible opaque generic-api-key must still detect; body={body}"
    );
}
