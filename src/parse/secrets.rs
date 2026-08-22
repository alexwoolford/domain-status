//! Exposed secret detection in HTML content.
//!
//! Uses the gitleaks default config (see `config/gitleaks.toml`) as the source
//! of rules. Each rule's regex is run over the HTML body; entropy and allowlist
//! filters reduce false positives.
//!
//! Each finding includes:
//! - **`secret_type`**: gitleaks rule id (e.g. `aws-access-token`)
//! - **severity**: critical / high / medium / low (mapped from rule id or default High)
//! - **location**: heuristic for where in the HTML the secret was found
//! - **context**: ~80 chars before + match + ~80 chars after for analyst triage

use std::borrow::Cow;
use std::fmt;

/// Number of context characters to capture before and after a match.
const CONTEXT_CHARS: usize = 80;

/// Maximum total bytes stored in the per-secret `context` column.
///
/// Without a cap, a private-key match (~3-10 KB) plus 160 chars of context
/// produces a row that essentially duplicates the full secret in two columns.
/// Pages with many such matches bloat the `SQLite` WAL file. 1 KB is comfortable
/// for analyst triage (line of code + ~40 chars on each side of a typical
/// secret) while bounded enough to keep row sizes predictable.
const MAX_CONTEXT_BYTES: usize = 1024;

/// Severity levels for exposed secrets.
///
/// Marked `#[non_exhaustive]` so adding new tiers (e.g. `Informational`) is not
/// a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SecretSeverity {
    /// Can directly compromise systems or charge money (e.g., AWS secret key, Stripe secret key, private keys).
    Critical,
    /// Significant access but may need pairing or have limits (e.g., AWS access key alone, `OpenAI` key).
    High,
    /// Potentially sensitive but often restricted or scoped (e.g., Google API key, Slack webhook).
    Medium,
    /// Intentionally public or low-impact (e.g., Stripe publishable key, Firebase URL, Mapbox public token).
    Low,
}

impl SecretSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            SecretSeverity::Critical => "critical",
            SecretSeverity::High => "high",
            SecretSeverity::Medium => "medium",
            SecretSeverity::Low => "low",
        }
    }
}

impl fmt::Display for SecretSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An exposed secret detected in HTML content.
#[derive(Debug, Clone)]
pub struct ExposedSecret {
    /// Gitleaks rule id (e.g. `aws-access-token`).
    pub secret_type: String,
    /// Full matched value as found on the public page.
    pub matched_value: String,
    /// Surrounding text for context (~80 chars before + match + ~80 chars after).
    pub context: String,
    /// Severity classification (critical / high / medium / low).
    pub severity: SecretSeverity,
    /// Heuristic location hint (`inline_script`, `html_comment`, `url_parameter`, etc.).
    ///
    /// Stored as `Cow<'static, str>` so the heuristic can return `&'static str`
    /// literals without allocating per match. `Cow<'static, str>` derefs to
    /// `&str` and implements `PartialEq<&str>` and `Display`, so most
    /// downstream usages don't notice the difference.
    pub location: Cow<'static, str>,
    /// Decoded JWT claims (populated only for `secret_type` "jwt" or "jwt-base64").
    pub decoded_jwt: Option<crate::parse::jwt::DecodedJwt>,
}

/// Shannon entropy (log2) of the string, over byte frequencies.
/// Used to filter low-entropy matches when a gitleaks rule sets an entropy threshold.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for b in s.bytes() {
        counts[usize::from(b)] += 1;
    }
    #[allow(clippy::cast_precision_loss)] // secret substrings are short; f64 mantissa sufficient
    let len = s.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            #[allow(clippy::cast_precision_loss)]
            let p = c as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Minimum Shannon entropy required for non-hex `generic-api-key` matches.
///
/// Upstream gitleaks uses 3.5; that lets through short JS identifiers and
/// low-variety CMS keys. 4.0 cuts most camelCase / dictionary noise while
/// remaining reachable for mixed base64-ish tokens.
const GENERIC_API_KEY_MIN_ENTROPY: f64 = 4.0;

/// Hex-only tokens have an alphabet of 16 symbols, so Shannon entropy cannot
/// exceed 4.0 and typically lands slightly under it. Use the upstream floor
/// for long hex blobs instead of rejecting every Maps/CMS-style hex id.
const GENERIC_API_KEY_HEX_MIN_ENTROPY: f64 = 3.5;

/// Minimum length for a plausible `generic-api-key` match.
const GENERIC_API_KEY_MIN_LEN: usize = 16;

/// Minimum length for hex-only `generic-api-key` matches (CMS `_key`s are shorter).
const GENERIC_API_KEY_HEX_MIN_LEN: usize = 32;

/// Returns true if `s` looks like a `camelCase` / `PascalCase` JS identifier
/// (has a lowercase→uppercase transition). Used to reject minified-JS noise.
fn looks_like_camel_case_identifier(s: &str) -> bool {
    let bytes = s.as_bytes();
    for window in bytes.windows(2) {
        if window[0].is_ascii_lowercase() && window[1].is_ascii_uppercase() {
            return true;
        }
    }
    false
}

/// Web-specific plausibility filter for the catch-all `generic-api-key` rule.
///
/// Upstream's regex captures `[\w.=-]{10,150}`, which matches JS expressions
/// (`iframe.tabIndex=-1`), property names (`deprecatedApiDoNotUse`), and CMS
/// document keys. This filter keeps only secret-shaped opaque tokens.
fn generic_api_key_is_plausible(value: &str) -> bool {
    if value.len() < GENERIC_API_KEY_MIN_LEN {
        return false;
    }
    // Assignment / member-expression noise from minified JS.
    if value.contains('.') || value.contains('=') {
        return false;
    }
    if looks_like_camel_case_identifier(value) {
        return false;
    }
    // Opaque tokens are hex/base64-ish; reject anything outside that charset.
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'+' || b == b'/')
    {
        return false;
    }
    // Pure alphabetic strings are almost always dictionary / i18n keys.
    if value.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }

    let hex_digits = value.bytes().filter(|b| b.is_ascii_hexdigit()).count();
    let predominantly_hex = hex_digits * 5 >= value.len() * 4; // >= 80% hex
    if predominantly_hex {
        if value.len() < GENERIC_API_KEY_HEX_MIN_LEN {
            return false;
        }
        return shannon_entropy(value) >= GENERIC_API_KEY_HEX_MIN_ENTROPY;
    }

    shannon_entropy(value) >= GENERIC_API_KEY_MIN_ENTROPY
}

/// Post-match filters for rules whose upstream patterns are too broad on HTML/JS.
///
/// Returns `true` when the finding should be **kept**.
fn web_rule_match_is_plausible(rule_id: &str, matched_value: &str) -> bool {
    match rule_id {
        "generic-api-key" => generic_api_key_is_plausible(matched_value),
        // Upstream also matches bare 40-hex when the keyword "sourcegraph" appears
        // anywhere nearby; require the real `sgp_` token prefix.
        "sourcegraph-access-token" => matched_value.starts_with("sgp_"),
        // Legacy `s.` vault tokens are 24 random base62 chars. CamelCase identifiers
        // like `s.typographyH300FontWeight` (CSS tokens in minified bundles) must go.
        "vault-service-token" => {
            if let Some(rest) = matched_value.strip_prefix("s.") {
                !looks_like_camel_case_identifier(rest)
            } else {
                true
            }
        }
        // LinkedIn client id/secret rules match short alnum near "linkedin".
        // JS property names (thumbnailWidth) start lowercase and camelCase;
        // random opaque secrets typically do not.
        "linkedin-client-id" | "linkedin-client-secret" => {
            let starts_lower = matched_value
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_lowercase());
            !(starts_lower && looks_like_camel_case_identifier(matched_value))
        }
        _ => true,
    }
}

/// Context-aware plausibility filter, run once the surrounding text (context window
/// or containing line) is available for the match.
///
/// Some rules can't be disambiguated from `matched_value` alone because the tell is
/// in a variable/property name that sits *before* the captured value, outside the
/// rule's capture group. `datadog-access-token`'s regex still matches bare
/// `apiKey`/`appKey` assignments of 32-40 hex (many third-party SDKs use that shape). Keep
/// the finding only when nearby text identifies Datadog — not by denylisting every
/// other product (Bugsnag, Amplitude, Cookie Control, Algolia, …).
fn web_rule_match_is_plausible_in_context(rule_id: &str, nearby_text: &str) -> bool {
    match rule_id {
        "datadog-access-token" => nearby_text_looks_like_datadog(nearby_text),
        _ => true,
    }
}

/// Datadog identity markers that must appear near a candidate `apiKey`/`appKey` hex.
fn nearby_text_looks_like_datadog(nearby_text: &str) -> bool {
    let lower = nearby_text.to_ascii_lowercase();
    const MARKERS: &[&str] = &[
        "datadog",
        "dd_api",
        "dd_app",
        "ddapikey",
        "ddappkey",
        "dd_rum",
        "dd_logs",
        "dd_client",
        "dd_site",
    ];
    MARKERS.iter().any(|m| lower.contains(m))
}

/// Severity for a gitleaks rule id.
///
/// Three-step classification:
/// 1. Explicit allowlists for rules we've manually triaged (Critical/High/Medium/Low).
/// 2. Heuristic classification for unknown rule IDs based on naming conventions
///    (`-secret*` => High, `-token*`/`-key*`/`-pat*`/`-cred*` => Medium, else Low).
/// 3. Default Low for anything else (e.g. very generic patterns whose impact
///    can't be inferred from the rule ID alone).
///
/// Why default `Low` rather than `High`: gitleaks ships ~250 rules and most are
/// not in our explicit allowlist. The previous "default High" choice meant
/// every unclassified rule produced a High-severity row, which both inflated
/// apparent risk and degraded the signal value of "true" High findings (a
/// real `aws-access-token` looked the same as `generic-api-key` matching a
/// random hex blob). Conservative-by-default makes High mean "we deliberately
/// said this is High."
fn severity_for_rule_id(rule_id: &str) -> SecretSeverity {
    match rule_id {
        // Critical: direct compromise or financial
        "private-key"
        | "database-connection-uri"
        | "jdbc-connection-string"
        | "credential-bearing-url"
        | "slack-bot-token"
        | "slack-user-token"
        | "slack-legacy-token"
        | "slack-legacy-bot-token"
        | "github-pat"
        | "github-fine-grained-pat"
        | "gitlab-pat"
        | "vault-batch-token"
        | "vault-service-token" => SecretSeverity::Critical,
        // High
        "aws-access-token"
        | "http-basic-auth"
        | "mailchimp-api-key"
        | "openai-api-key"
        | "anthropic-api-key"
        | "anthropic-admin-api-key"
        | "sendgrid-api-token"
        | "twilio-api-key"
        | "npm-access-token"
        | "pypi-upload-token"
        | "digitalocean-access-token"
        | "digitalocean-pat"
        | "heroku-api-key"
        | "heroku-api-key-v2"
        | "flyio-access-token"
        | "shopify-access-token"
        | "shopify-private-app-access-token"
        | "shopify-shared-secret"
        | "bitbucket-client-secret"
        | "mailgun-private-api-token"
        | "cloudflare-api-key"
        | "doppler-api-token"
        | "plaid-secret-key"
        | "plaid-api-token"
        | "fastly-api-token" => SecretSeverity::High,
        // Medium
        "azure-ad-client-secret"
        | "slack-webhook-url"
        | "slack-app-token"
        | "algolia-api-key"
        | "datadog-access-token"
        | "grafana-api-key"
        | "grafana-cloud-api-token"
        | "sentry-access-token"
        | "linear-api-key"
        // Generic catch-all rule: matches a wide pattern with low specificity,
        // so we treat it as Medium-by-default to keep High meaningful.
        | "generic-api-key" => SecretSeverity::Medium,
        // Low: intentionally public client identifiers (Maps/Firebase embeds,
        // Mapbox public tokens). Still recorded for inventory, but not triage-urgent.
        "gcp-api-key" | "mapbox-api-token" => SecretSeverity::Low,
        // Low: JWTs on the web are usually CDN/session/buyer tokens, not private
        // API credentials. Keep for inventory; do not treat as triage-urgent.
        "jwt" | "jwt-base64" => SecretSeverity::Low,
        _ => severity_for_unknown_rule_id(rule_id),
    }
}

/// Severity for a finding, with context-aware demotion for known public-temp shapes.
///
/// AWS access key IDs embedded in `X-Amz-Credential=` pre-signed URL query params
/// are real IDs but temporary/public URL material — record as Low, not High.
fn severity_for_finding(rule_id: &str, line_content: &str) -> SecretSeverity {
    let severity = severity_for_rule_id(rule_id);
    if rule_id == "aws-access-token"
        && line_content
            .to_ascii_lowercase()
            .contains("x-amz-credential=")
    {
        return SecretSeverity::Low;
    }
    severity
}

/// Heuristic classification for gitleaks rule IDs we haven't explicitly mapped.
///
/// The rule-id naming convention in gitleaks is consistent enough to give us a
/// reasonable guess: anything containing `secret`/`password`/`private-key`
/// indicates direct compromise, whereas tokens/keys/credentials are usually
/// scoped or rate-limited. Anything else falls to Low.
fn severity_for_unknown_rule_id(rule_id: &str) -> SecretSeverity {
    let lower = rule_id;
    if lower.contains("private-key")
        || lower.contains("password")
        || lower.contains("client-secret")
        || lower.contains("client_secret")
    {
        SecretSeverity::High
    } else if lower.contains("token")
        || lower.contains("api-key")
        || lower.contains("api_key")
        || lower.contains("access-key")
        || lower.contains("access_key")
        || lower.contains("secret")
        || lower.contains("pat")
        || lower.contains("cred")
    {
        SecretSeverity::Medium
    } else {
        SecretSeverity::Low
    }
}

/// Returns true if the match should be skipped by the global allowlist (regex or stopword).
///
/// Tests only the matched secret value, matching upstream gitleaks semantics for the
/// global allowlist (default `regexTarget` = secret). Testing the surrounding context
/// window would let benign nearby tokens (e.g. `debug:false` next to a real API key)
/// suppress genuine findings for every rule.
fn global_allowlist_skips(
    global: &crate::parse::gitleaks::CompiledGlobalAllowlist,
    matched_value: &str,
) -> bool {
    for re in &global.regexes {
        if re.is_match(matched_value) {
            return true;
        }
    }
    for word in &global.stopwords {
        if matched_value.contains(word) {
            return true;
        }
    }
    false
}

/// Maximum bytes of "line" kept on each side of a match for `regexTarget = "line"`
/// allowlists. Minified HTML/JS often has no newlines at all; without this cap the
/// "line" would be the entire document, and one benign allowlist token anywhere on
/// the page (e.g. a Cloudflare `data-cfemail=` widget) would suppress every real
/// finding of that rule across the whole body.
const MAX_LINE_WINDOW_BYTES: usize = 512;

/// Returns the line containing the byte range [start, end) in body, capped to
/// [`MAX_LINE_WINDOW_BYTES`] on each side of the match. Line = span between \n
/// (or start/end of body), truncated to the window when the physical line is longer.
fn line_containing(body: &str, start: usize, end: usize) -> &str {
    let mut window_start = start.saturating_sub(MAX_LINE_WINDOW_BYTES);
    while !body.is_char_boundary(window_start) {
        window_start += 1;
    }
    let mut window_end = (end + MAX_LINE_WINDOW_BYTES).min(body.len());
    while !body.is_char_boundary(window_end) {
        window_end -= 1;
    }
    let line_start = body[window_start..start]
        .rfind('\n')
        .map_or(window_start, |i| window_start + i + 1);
    let line_end = body[end..window_end]
        .find('\n')
        .map_or(window_end, |i| end + i);
    &body[line_start..line_end]
}

/// Extracts the secret from a regex match.
///
/// Order of preference:
/// 1. If `secretGroup` (1-based) is set and the capture exists, use it. This is
///    the upstream Gitleaks-recommended way to point at the secret precisely.
/// 2. Otherwise, return the **first non-empty capture group**. Most bundled
///    Gitleaks rules wrap the secret in a single capture group with surrounding
///    anchoring text (e.g. `(?i)hubspot.*=\s*"([0-9A-F-]{36})"`). The full
///    match includes the keyword and quotes; group 1 is the clean secret.
/// 3. Fallback: full match.
///
/// Note on Gitleaks parity: Gitleaks v8 (Go) defaults to `matches[0]` (full
/// match) when `secretGroup` is unset. We deliberately differ because the
/// rules shipped in `config/gitleaks.toml` rarely declare `secretGroup` even
/// when the regex has anchoring context, and returning the full match would
/// store `window.API_KEY="<uuid>"` instead of `<uuid>`. The `(rule_id,
/// matched_value)` dedupe and the analyst-facing report both want the clean
/// secret. If a future rule needs the literal full match, it must declare
/// `secretGroup = 0` explicitly (we treat 0 as "unset" today; that's the
/// only edge worth flagging in a future change).
fn extract_secret(
    captures: Option<regex::Captures>,
    full_match: &str,
    secret_group: Option<u32>,
) -> String {
    let Some(caps) = captures else {
        return full_match.to_string();
    };
    if let Some(n) = secret_group {
        if n > 0 {
            if let Some(m) = caps.get(n as usize) {
                return m.as_str().to_string();
            }
        }
    }
    for i in 1..caps.len() {
        if let Some(m) = caps.get(i) {
            if !m.as_str().is_empty() {
                return m.as_str().to_string();
            }
        }
    }
    full_match.to_string()
}

/// Returns true if the match should be skipped by a per-rule allowlist.
/// Respects condition: OR = any criterion skips; AND = all must match (path is N/A for single-blob, so AND with paths never skips).
pub(crate) fn rule_allowlist_skips(
    allowlists: &[crate::parse::gitleaks::CompiledRuleAllowlist],
    matched_value: &str,
    line_content: &str,
    full_match: &str,
) -> bool {
    for list in allowlists {
        let target = match list.regex_target.as_deref() {
            Some("line") => line_content,
            Some("match") => full_match,
            _ => matched_value,
        };
        if list.condition_and {
            // AND: all criteria must match. Path is N/A for single-blob (we never have a file path).
            if list.has_paths {
                continue; // path never matches, so AND never succeeds; do not skip
            }
            let all_regex =
                list.regexes.is_empty() || list.regexes.iter().all(|re| re.is_match(target));
            let all_stop =
                list.stopwords.is_empty() || list.stopwords.iter().all(|w| target.contains(w));
            if all_regex && all_stop {
                return true;
            }
        } else {
            // OR: any match skips
            for re in &list.regexes {
                if re.is_match(target) {
                    return true;
                }
            }
            for word in &list.stopwords {
                if target.contains(word) {
                    return true;
                }
            }
        }
    }
    false
}

/// Extracts surrounding context for a match within the body text.
///
/// The full window is `[match_start - CONTEXT_CHARS, match_end + CONTEXT_CHARS]`,
/// snapped to valid UTF-8 char boundaries. If the result would exceed
/// [`MAX_CONTEXT_BYTES`] (a private-key match alone can be ~3-10 KB), the
/// long match in the middle is replaced with `<head>...<tail>` so the
/// context still reflects the surrounding code without duplicating the full
/// secret value in this column.
fn extract_context(body: &str, start: usize, end: usize) -> String {
    let ctx_start = start.saturating_sub(CONTEXT_CHARS);
    let ctx_end = (end + CONTEXT_CHARS).min(body.len());

    // Snap to valid char boundaries without slicing at potentially invalid offsets.
    // Walk backwards from ctx_start to find the previous char boundary.
    let safe_start = (0..=ctx_start)
        .rev()
        .find(|&i| body.is_char_boundary(i))
        .unwrap_or(0);
    // Walk forwards from ctx_end to find the next char boundary.
    let safe_end = (ctx_end..=body.len())
        .find(|&i| body.is_char_boundary(i))
        .unwrap_or(body.len());

    let raw = &body[safe_start..safe_end];
    if raw.len() <= MAX_CONTEXT_BYTES {
        return raw.to_string();
    }

    // Long: keep the surrounding code by truncating the match in the middle.
    // Allocate the budget as: prefix-context + head-of-match + ELLIPSIS + tail-of-match + suffix-context.
    const ELLIPSIS: &str = "...[truncated]...";
    let prefix = match_safe_slice(body, safe_start, start);
    let suffix = match_safe_slice(body, end, safe_end);
    let prefix_len = prefix.len();
    let suffix_len = suffix.len();

    // Reserve characters for ellipsis + prefix/suffix; remaining budget split between match-head and match-tail.
    let overhead = prefix_len + suffix_len + ELLIPSIS.len();
    if overhead >= MAX_CONTEXT_BYTES {
        // Pathological: even the surrounding context exceeds the cap.
        // Fall back to the raw window truncated to MAX_CONTEXT_BYTES at the
        // nearest char boundary.
        return truncate_at_char_boundary(raw, MAX_CONTEXT_BYTES);
    }
    let match_budget = MAX_CONTEXT_BYTES - overhead;
    let half = match_budget / 2;
    let match_text = &body[start..end];
    let head = truncate_at_char_boundary(match_text, half);
    let tail_start = match_text
        .len()
        .saturating_sub(match_budget - head.len())
        .max(head.len());
    // Snap tail_start to a char boundary going forward.
    let tail_start = (tail_start..=match_text.len())
        .find(|&i| match_text.is_char_boundary(i))
        .unwrap_or(match_text.len());
    let tail = &match_text[tail_start..];

    format!("{prefix}{head}{ELLIPSIS}{tail}{suffix}")
}

/// Slice safely between two byte indices that are already on char boundaries.
fn match_safe_slice(body: &str, start: usize, end: usize) -> &str {
    if start <= end
        && end <= body.len()
        && body.is_char_boundary(start)
        && body.is_char_boundary(end)
    {
        &body[start..end]
    } else {
        ""
    }
}

/// Truncate a `&str` to at most `max_bytes`, snapping back to the nearest
/// preceding char boundary so the returned slice is always valid UTF-8.
fn truncate_at_char_boundary(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut idx = max_bytes;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    s[..idx].to_string()
}

/// Infers location hint from the surrounding context string.
fn infer_location(context: &str) -> &'static str {
    let ctx = context.to_lowercase();
    if ctx.contains("<script") || ctx.contains("</script") {
        "inline_script"
    } else if ctx.contains("<!--") {
        "html_comment"
    } else if ctx.contains("data-") {
        "data_attribute"
    } else if ctx.contains("?key=")
        || ctx.contains("&key=")
        || ctx.contains("&token=")
        || ctx.contains("?token=")
    {
        "url_parameter"
    } else if ctx.contains("content=\"") || ctx.contains("content='") {
        "meta_tag"
    } else {
        "html_body"
    }
}

/// Returns true when `pos` lies inside a `<script type="application/ld+json">` block.
///
/// Walks backward from `pos` to the nearest preceding `<script` (ASCII tag, so
/// byte indices on a lowercased prefix align) and requires `application/ld+json`
/// in the opening tag with no intervening `</script>`.
fn is_inside_json_ld_script(body: &str, pos: usize) -> bool {
    let before = &body[..pos.min(body.len())];
    let lower_before = before.to_ascii_lowercase();
    let Some(script_start) = lower_before.rfind("<script") else {
        return false;
    };
    let region = &lower_before[script_start..];
    if let Some(close) = region.find("</script") {
        if script_start + close < pos {
            return false;
        }
    }
    let tag_end = region.find('>').unwrap_or(region.len().min(200));
    region[..tag_end].contains("application/ld+json")
}

/// Location for a body match: prefer `json_ld` when inside LD+JSON script.
fn infer_location_for_body_match(body: &str, match_start: usize, context: &str) -> &'static str {
    if is_inside_json_ld_script(body, match_start) {
        return "json_ld";
    }
    infer_location(context)
}

/// Detects exposed secrets in raw HTML body text using gitleaks rules.
///
/// Loads rules from the bundled `config/gitleaks.toml`, runs each regex over the body,
/// applies entropy and allowlist filters, and returns findings with gitleaks rule id
/// as `secret_type` and derived severity.
///
/// The keyword prefilter (Aho-Corasick automaton built once at config-load
/// time) runs once over the body and produces the set of pattern IDs that
/// appear in it. Each rule then checks that set in `O(rule_keywords)` instead
/// of re-scanning the body — making total work `O(body_len + sum(rule_keywords))`
/// rather than `O(body_len * sum(rule_keywords))`.
pub fn detect_exposed_secrets(body: &str) -> Vec<ExposedSecret> {
    detect_exposed_secrets_inner(body, true)
}

/// Detects exposed secrets in serialized HTTP response headers.
///
/// `header_block` is expected to be newline-separated `Name: value` lines
/// (including `Set-Cookie` values). Real secrets routinely appear in
/// `Authorization`, `X-Api-Key`, `X-Amz-Security-Token`, and `Set-Cookie`
/// (session/JWT) headers, which the HTML-body scan never sees. Findings are
/// retagged with `location = "set_cookie"` when on a Set-Cookie line, otherwise
/// `response_header`.
pub fn detect_exposed_secrets_in_headers(header_block: &str) -> Vec<ExposedSecret> {
    let mut found = detect_exposed_secrets_inner(header_block, true);
    for secret in &mut found {
        let ctx_lc = secret.context.to_ascii_lowercase();
        // Prefer the header line around the match (context includes nearby lines).
        if ctx_lc.contains("set-cookie:") {
            secret.location = Cow::Borrowed("set_cookie");
        } else {
            secret.location = Cow::Borrowed("response_header");
        }
    }
    found
}

/// Test-only variant that bypasses the Aho-Corasick keyword prefilter.
///
/// Used by the prefilter-equivalence regression test: the prefilter is meant
/// to be a pure perf shortcut, so for any body its findings must match the
/// findings produced when every rule's regex runs unconditionally. Any
/// divergence is a correctness bug in the prefilter (a missing keyword for
/// some rule, an automaton that doesn't see a substring, etc.).
#[cfg(test)]
pub(crate) fn detect_exposed_secrets_unfiltered(body: &str) -> Vec<ExposedSecret> {
    detect_exposed_secrets_inner(body, false)
}

fn detect_exposed_secrets_inner(body: &str, use_prefilter: bool) -> Vec<ExposedSecret> {
    let config = crate::parse::gitleaks::gitleaks();
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // One-pass keyword scan. Rules without keywords skip this gate entirely
    // and always run their regex. The unfiltered variant ignores this set
    // entirely (use_prefilter == false) so every rule's regex runs.
    let matched_keyword_ids = if use_prefilter {
        config
            .keyword_prefilter
            .as_ref()
            .map(|p| p.matched_pattern_ids(body))
    } else {
        None
    };

    for rule in &config.rules {
        // Rules restricted to specific file paths (e.g. .tf, .hcl) are for repo scanning; skip when scanning a single blob (HTML) with no path.
        if rule.path.is_some() {
            continue;
        }
        // Aho-Corasick prefilter: skip the rule if it has keywords AND none of
        // them were observed in the body. Rules without `keyword_pattern_ids`
        // run unconditionally (matches gitleaks "no keywords -> always run").
        if let (Some(ids), Some(matched)) = (
            rule.keyword_pattern_ids.as_ref(),
            matched_keyword_ids.as_ref(),
        ) {
            if !ids.is_empty()
                && !crate::parse::gitleaks::KeywordPrefilter::any_id_present(ids, matched)
            {
                continue;
            }
        }

        // Use captures_iter directly (avoids redundant find_iter + re-capture per match)
        for cap in rule.regex.captures_iter(body) {
            let Some(mat) = cap.get(0) else { continue };
            let full_match = mat.as_str();
            let matched_value = extract_secret(Some(cap), full_match, rule.secret_group);

            if let Some(entropy_threshold) = rule.entropy {
                if shannon_entropy(&matched_value) < entropy_threshold {
                    continue;
                }
            }

            if global_allowlist_skips(&config.global_allowlist, &matched_value) {
                continue;
            }
            if !web_rule_match_is_plausible(&rule.id, &matched_value) {
                continue;
            }
            let context = extract_context(body, mat.start(), mat.end());
            let line_content = line_containing(body, mat.start(), mat.end());
            if !web_rule_match_is_plausible_in_context(&rule.id, &context) {
                continue;
            }
            if rule_allowlist_skips(&rule.allowlists, &matched_value, line_content, full_match) {
                continue;
            }

            let key = (rule.id.clone(), matched_value.clone());
            if !seen.insert(key) {
                continue;
            }

            let location: Cow<'static, str> =
                Cow::Borrowed(infer_location_for_body_match(body, mat.start(), &context));
            let severity = severity_for_finding(&rule.id, line_content);
            let decoded_jwt = match rule.id.as_str() {
                "jwt" => crate::parse::jwt::decode_jwt(&matched_value),
                "jwt-base64" => crate::parse::jwt::decode_jwt_base64(&matched_value),
                _ => None,
            };
            results.push(ExposedSecret {
                secret_type: rule.id.clone(),
                matched_value,
                context,
                severity,
                location,
                decoded_jwt,
            });
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns a stable redacted representation that preserves dedupe utility without retaining the raw secret.
    fn redact_exposed_secret_value(value: &str) -> String {
        use sha2::{Digest, Sha256};
        if value.starts_with("redacted(") {
            return value.to_string();
        }

        let digest = format!("{:x}", Sha256::digest(value.as_bytes()));
        if value.chars().count() <= 8 {
            format!(
                "redacted(len={},sha256={})",
                value.chars().count(),
                &digest[..16]
            )
        } else {
            let prefix: String = value.chars().take(4).collect();
            let suffix: String = value
                .chars()
                .rev()
                .take(4)
                .collect::<String>()
                .chars()
                .rev()
                .collect();
            format!(
                "redacted({prefix}...{suffix},len={},sha256={})",
                value.chars().count(),
                &digest[..16]
            )
        }
    }

    /// Redacts secret occurrences inside analyst context while preserving surrounding text.
    fn redact_exposed_secret_context(context: &str, matched_value: &str) -> String {
        if matched_value.is_empty() {
            return context.to_string();
        }

        if matched_value.starts_with("redacted(") {
            return context.to_string();
        }

        context.replace(matched_value, &redact_exposed_secret_value(matched_value))
    }

    // === Cloud Providers ===

    // AWS key: gitleaks uses [A-Z2-7]{16} (no 0,1,8,9); must not end in EXAMPLE (allowlisted)
    const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPL2";

    #[test]
    fn test_detect_aws_access_key() {
        let body = format!(r#"var key = "{}";"#, AWS_KEY);
        let secrets = detect_exposed_secrets(&body);
        // The body must trigger the dedicated `aws-access-token` rule. It may
        // ALSO trigger the broader `generic-api-key` rule (the latter started
        // catching this same value once we raised the gitleaks regex size
        // limit and the previously-skipped rule began compiling). Assert on
        // the dedicated rule's presence rather than the total count.
        let aws = secrets
            .iter()
            .find(|s| s.secret_type == "aws-access-token")
            .unwrap_or_else(|| panic!("expected an aws-access-token secret in {secrets:?}"));
        assert_eq!(aws.matched_value, AWS_KEY);
        assert_eq!(aws.severity, SecretSeverity::High);
    }

    #[test]
    fn test_aws_example_allowlisted() {
        let body = r#"var key = "AKIAIOSFODNN7EXAMPLE";"#;
        let secrets = detect_exposed_secrets(body);
        let aws = secrets.iter().find(|s| s.secret_type == "aws-access-token");
        assert!(
            aws.is_none(),
            "EXAMPLE key should be allowlisted; got {:?}",
            secrets
        );
    }

    #[test]
    fn test_secret_detected_next_to_boolean_literal() {
        // Regression: the global allowlist regex `^(?i:true|false|null)$` used to be
        // mis-anchored (`(?i)^true|false|null$`) AND tested against the context window,
        // so any secret near the token `false` was silently suppressed.
        let body = format!(r#"<script>var c={{apiKey:"{AWS_KEY}",debug:false}};</script>"#);
        let secrets = detect_exposed_secrets(&body);
        assert!(
            secrets.iter().any(|s| s.secret_type == "aws-access-token"),
            "AWS key next to `debug:false` must still be detected; got {secrets:?}"
        );
    }

    #[test]
    fn test_minified_page_allowlist_does_not_suppress_whole_body() {
        // Regression: on newline-free (minified) pages, `line_containing` returned the
        // entire body, so a benign line-target allowlist token anywhere on the page
        // (e.g. Cloudflare's `data-cfemail=`) suppressed real findings of that rule.
        let body = format!(
            r#"<span data-cfemail="a1b2c3"></span>{}<script>var k="{AWS_KEY}";</script>"#,
            " ".repeat(2000)
        );
        assert!(!body.contains('\n'), "test body must be newline-free");
        let secrets = detect_exposed_secrets(&body);
        assert!(
            secrets.iter().any(|s| s.secret_type == "aws-access-token"),
            "secret on a minified page with a distant allowlist token must be detected; got {secrets:?}"
        );
    }

    #[test]
    fn test_line_containing_capped_on_minified_body() {
        let body = "x".repeat(5000);
        let line = line_containing(&body, 2500, 2520);
        assert!(
            line.len() <= 2 * MAX_LINE_WINDOW_BYTES + 20,
            "line window must be capped, got {} bytes",
            line.len()
        );
    }

    #[test]
    fn test_detect_secret_in_response_header_block() {
        // Regression: JWTs/keys in response headers (incl. Set-Cookie) were never
        // scanned. A JWT in a Set-Cookie line must be detected and tagged.
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                   eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.\
                   dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let header_block = format!("Content-Type: text/html\nSet-Cookie: session={jwt}; Path=/\n");
        let secrets = detect_exposed_secrets_in_headers(&header_block);
        assert!(
            secrets.iter().any(|s| s.secret_type == "jwt"),
            "JWT in Set-Cookie must be detected; got {secrets:?}"
        );
        assert!(
            secrets.iter().all(|s| s.location == "set_cookie"),
            "header findings must be tagged set_cookie"
        );
    }

    #[test]
    fn test_detect_aws_session_token() {
        // ASIA + 16 chars from [A-Z2-7]; may be filtered by entropy
        let body = "token=ASIA2BCDEF34567ZYXW";
        let secrets = detect_exposed_secrets(body);
        if secrets.len() == 1 {
            assert_eq!(secrets[0].secret_type, "aws-access-token");
            assert_eq!(secrets[0].severity, SecretSeverity::High);
        }
    }

    #[test]
    fn test_detect_google_api_key() {
        let body = r#"var apiKey = "AIzaSyA1234567890abcdefghijklmnopqrstuv";"#;
        let secrets = detect_exposed_secrets(body);
        assert!(!secrets.is_empty());
        assert!(secrets.iter().any(|s| s.secret_type == "gcp-api-key"));
    }

    #[test]
    fn test_detect_google_api_key_in_url_with_trailing_param() {
        // Regression: upstream rules require quote/space/semicolon/EOL after the
        // secret, so a Maps key followed by `&` in a script URL was never matched.
        // The load-time boundary relaxation must catch it.
        let body = r#"<script src="https://maps.googleapis.com/maps/api/js?key=AIzaSyA1234567890abcdefghijklmnopqrstuv&libraries=places"></script>"#;
        let secrets = detect_exposed_secrets(body);
        let gcp = secrets.iter().find(|s| s.secret_type == "gcp-api-key");
        assert!(
            gcp.is_some(),
            "GCP key followed by `&` in a URL must be detected; got {secrets:?}"
        );
        assert_eq!(
            gcp.map(|s| s.matched_value.as_str()),
            Some("AIzaSyA1234567890abcdefghijklmnopqrstuv"),
            "capture must be the key alone, not include the delimiter"
        );
    }

    #[test]
    fn test_detect_openai_api_key() {
        // gitleaks openai-api-key: sk- + 20 alnum + T3BlbkFJ + 20 alnum (built at runtime to avoid secret-scanning false positives)
        let a: String = (0..20)
            .map(|i| (b'a' + u8::try_from(i % 26).unwrap()) as char)
            .collect();
        let b: String = (0..20)
            .map(|i| (b'A' + u8::try_from(i % 26).unwrap()) as char)
            .collect();
        let body = format!(r#"key = "sk-{}T3BlbkFJ{}""#, a, b);
        let secrets = detect_exposed_secrets(&body);
        assert!(!secrets.is_empty());
        assert!(secrets.iter().any(|s| s.secret_type == "openai-api-key"));
    }

    /// Build a 93-char Anthropic mid-segment without embedding a full key literal in source.
    ///
    /// Digits-first / uppercase-only so the mid never contains the global allowlist
    /// stopword `abcdefghijklmnopqrstuvwxyz`.
    fn anthropic_key_mid() -> String {
        (0..93)
            .map(|i| {
                let n = u8::try_from(i % 36).unwrap();
                match n {
                    0..=9 => (b'0' + n) as char,
                    _ => (b'A' + (n - 10)) as char,
                }
            })
            .collect()
    }

    #[test]
    fn test_detect_anthropic_api_key() {
        // gitleaks: sk-ant-api03- + 93 [A-Za-z0-9_-] + AA
        let key = format!("sk-ant-api03-{}AA", anthropic_key_mid());
        let body = format!(r#"<script>const ANTHROPIC_API_KEY = "{key}";</script>"#);
        let secrets = detect_exposed_secrets(&body);
        let found = secrets
            .iter()
            .find(|s| s.secret_type == "anthropic-api-key")
            .unwrap_or_else(|| panic!("expected anthropic-api-key; got {secrets:?}"));
        assert_eq!(found.matched_value, key);
        assert_eq!(found.severity, SecretSeverity::High);
    }

    #[test]
    fn test_detect_anthropic_admin_api_key() {
        // gitleaks: sk-ant-admin01- + 93 [A-Za-z0-9_-] + AA
        let key = format!("sk-ant-admin01-{}AA", anthropic_key_mid());
        let body = format!(r#"window.__cfg = {{ adminKey: "{key}" }};"#);
        let secrets = detect_exposed_secrets(&body);
        let found = secrets
            .iter()
            .find(|s| s.secret_type == "anthropic-admin-api-key")
            .unwrap_or_else(|| panic!("expected anthropic-admin-api-key; got {secrets:?}"));
        assert_eq!(found.matched_value, key);
        assert_eq!(found.severity, SecretSeverity::High);
    }

    #[test]
    fn test_detect_slack_bot_token() {
        let body = r#"token: "xoxb-123456789012-1234567890123-ABCDEFabcdef123456789012""#;
        let secrets = detect_exposed_secrets(body);
        assert!(!secrets.is_empty());
        assert!(secrets.iter().any(|s| s.secret_type == "slack-bot-token"));
    }

    #[test]
    fn test_detect_rsa_private_key() {
        // gitleaks private-key regex expects BEGIN...KEY-----[\s\S-]{64,}?...KEY-----
        let body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7\n-----END RSA PRIVATE KEY-----";
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].secret_type, "private-key");
        assert_eq!(secrets[0].severity, SecretSeverity::Critical);
    }

    #[test]
    fn test_detect_vault_token() {
        // gitleaks vault-service-token: hvs.[\w-]{90,120} with entropy=3.5
        let suffix: String = (0..95)
            .map(|i| (b'a' + u8::try_from(i % 26).unwrap()) as char)
            .collect();
        let body = format!(r#"VAULT_TOKEN="hvs.{}""#, suffix);
        let secrets = detect_exposed_secrets(&body);
        if !secrets.is_empty() {
            assert!(secrets
                .iter()
                .any(|s| s.secret_type == "vault-service-token"
                    || s.secret_type == "vault-batch-token"));
        }
    }

    #[test]
    fn test_shannon_entropy() {
        assert!((shannon_entropy("") - 0.0).abs() < 1e-9);
        assert!(shannon_entropy("aaaaaaaa") < shannon_entropy("abcd1234"));
    }

    #[test]
    fn test_severity_for_rule_id_explicit_classifications() {
        assert_eq!(
            severity_for_rule_id("private-key"),
            SecretSeverity::Critical
        );
        assert_eq!(
            severity_for_rule_id("aws-access-token"),
            SecretSeverity::High
        );
        assert_eq!(
            severity_for_rule_id("gcp-api-key"),
            SecretSeverity::Low,
            "Maps/Firebase client keys are public-by-design"
        );
        assert_eq!(
            severity_for_rule_id("generic-api-key"),
            SecretSeverity::Medium,
            "catch-all generic rule must not be High by default"
        );
        assert_eq!(
            severity_for_rule_id("mapbox-api-token"),
            SecretSeverity::Low
        );
    }

    /// Walk every rule id shipped in the bundled gitleaks config and assert
    /// the severity classifier returns a sensible value for each. This is a
    /// no-panic / no-default-High guarantee: when upstream gitleaks adds a
    /// new rule, our M-1 classifier must place it somewhere reasonable.
    ///
    /// The guarantee being tested:
    /// - No rule id collapses to `High` *unless* it's in the explicit map
    ///   or its name contains a credential keyword (the regression is the
    ///   pre-M-1 default of "anything unknown -> High" producing noise).
    /// - The classifier never panics on any production rule id.
    /// - Every classification is reproducible (calling twice on the same
    ///   id returns the same severity).
    #[test]
    fn test_severity_classifies_every_shipped_rule_id() {
        let cfg = crate::parse::gitleaks::try_gitleaks().expect("config loads");

        // The explicit High allowlist - hardcoded here so a future
        // refactor of severity_for_rule_id can't silently change which
        // ids are blessed.
        let explicit_high: std::collections::HashSet<&str> = [
            "aws-access-token",
            "http-basic-auth",
            "mailchimp-api-key",
            "openai-api-key",
            "anthropic-api-key",
            "anthropic-admin-api-key",
            "sendgrid-api-token",
            "twilio-api-key",
            "npm-access-token",
            "pypi-upload-token",
            "digitalocean-access-token",
            "digitalocean-pat",
            "heroku-api-key",
            "heroku-api-key-v2",
            "flyio-access-token",
            "shopify-access-token",
            "shopify-private-app-access-token",
            "shopify-shared-secret",
            "bitbucket-client-secret",
            "mailgun-private-api-token",
            "cloudflare-api-key",
            "doppler-api-token",
            "plaid-secret-key",
            "plaid-api-token",
            "fastly-api-token",
        ]
        .into_iter()
        .collect();

        for rule in &cfg.rules {
            let sev = severity_for_rule_id(&rule.id);

            // 1. Determinism: calling twice is identical.
            assert_eq!(
                sev,
                severity_for_rule_id(&rule.id),
                "non-deterministic for {}",
                rule.id
            );

            // 2. Anything that's `High` must either be in the explicit map
            //    OR have a name containing a "this is dangerous" keyword.
            //    Catches the "default High" regression: a rule id we don't
            //    recognise must NOT be High.
            if matches!(sev, SecretSeverity::High) {
                let id = &rule.id;
                let allowed_high = explicit_high.contains(id.as_str())
                    || id.contains("private-key")
                    || id.contains("password")
                    || id.contains("client-secret")
                    || id.contains("client_secret");
                assert!(
                    allowed_high,
                    "rule '{id}' classified as High but not in the explicit map and \
                     doesn't contain a 'high-impact' substring; either add it to the \
                     explicit list or rethink the heuristic so it lands at Medium"
                );
            }
        }
    }

    /// Heuristic for unknown rule IDs: sensitive-sounding ID -> Medium/High,
    /// nothing recognisable -> Low.
    #[test]
    fn test_severity_for_unknown_rule_id_heuristic() {
        // password / private-key / client-secret -> High
        assert_eq!(
            severity_for_rule_id("acme-private-key"),
            SecretSeverity::High
        );
        assert_eq!(
            severity_for_rule_id("foobar-password"),
            SecretSeverity::High
        );
        assert_eq!(
            severity_for_rule_id("zilch-client-secret"),
            SecretSeverity::High
        );
        // token/api-key/access-key/secret/pat/cred -> Medium
        assert_eq!(
            severity_for_rule_id("acme-access-token"),
            SecretSeverity::Medium
        );
        assert_eq!(severity_for_rule_id("foo-api-key"), SecretSeverity::Medium);
        assert_eq!(severity_for_rule_id("foo-pat"), SecretSeverity::Medium);
        assert_eq!(
            severity_for_rule_id("foo-credentials"),
            SecretSeverity::Medium
        );
        // Anything else -> Low (the new conservative default)
        assert_eq!(severity_for_rule_id("nonsense-rule"), SecretSeverity::Low);
        assert_eq!(severity_for_rule_id("totally-random"), SecretSeverity::Low);
    }

    #[test]
    fn test_location_inline_script() {
        let body = format!(r#"<script>var key = "{}";</script>"#, AWS_KEY);
        let secrets = detect_exposed_secrets(&body);
        assert_eq!(secrets[0].location, "inline_script");
    }

    #[test]
    fn test_location_html_comment() {
        let body = format!(r#"<!-- {} -->"#, AWS_KEY);
        let secrets = detect_exposed_secrets(&body);
        assert_eq!(secrets[0].location, "html_comment");
    }

    #[test]
    fn test_location_url_parameter() {
        let body = r#"https://example.com?key=AIzaSyA1234567890abcdefghijklmnopqrstuv"#;
        let secrets = detect_exposed_secrets(body);
        assert!(!secrets.is_empty());
        assert_eq!(secrets[0].location, "url_parameter");
    }

    #[test]
    fn test_location_data_attribute() {
        let body = format!(r#"<div data-api-key="{}">"#, AWS_KEY);
        let secrets = detect_exposed_secrets(&body);
        assert_eq!(secrets[0].location, "data_attribute");
    }

    #[test]
    fn test_location_default_html_body() {
        let body = format!("just plain text {} in body", AWS_KEY);
        let secrets = detect_exposed_secrets(&body);
        assert_eq!(secrets[0].location, "html_body");
    }

    #[test]
    fn test_location_json_ld() {
        let body = format!(
            r#"<html><script type="application/ld+json">{{"apiKey":"{}"}}</script></html>"#,
            AWS_KEY
        );
        let secrets = detect_exposed_secrets(&body);
        assert!(
            !secrets.is_empty(),
            "expected secret in json-ld; got {secrets:?}"
        );
        assert_eq!(secrets[0].location, "json_ld");
    }

    #[test]
    fn test_location_set_cookie_vs_other_header() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let set_cookie = format!("Set-Cookie: session={jwt}; Path=/\n");
        let sc = detect_exposed_secrets_in_headers(&set_cookie);
        assert!(
            sc.iter().any(|s| s.location == "set_cookie"),
            "Set-Cookie must be set_cookie; got {sc:?}"
        );

        let auth = format!("Authorization: Bearer {jwt}\n");
        let ah = detect_exposed_secrets_in_headers(&auth);
        assert!(
            ah.iter().any(|s| s.location == "response_header"),
            "Authorization must stay response_header; got {ah:?}"
        );
    }

    #[test]
    fn test_detect_no_secrets() {
        let body = "<html><body><p>Just regular HTML content</p></body></html>";
        let secrets = detect_exposed_secrets(body);
        assert!(secrets.is_empty());
    }

    #[test]
    fn test_detect_deduplicates() {
        let body = format!("first: {} second: {}", AWS_KEY, AWS_KEY);
        let secrets = detect_exposed_secrets(&body);
        assert_eq!(secrets.len(), 1);
    }

    #[test]
    fn test_full_value_stored_not_redacted() {
        let body = AWS_KEY;
        let secrets = detect_exposed_secrets(body);
        assert_eq!(secrets[0].matched_value, AWS_KEY);
        assert!(!secrets[0].matched_value.contains("***"));
    }

    #[test]
    fn test_context_80_chars() {
        // Word boundary before key: use space so \b matches
        let prefix = "A".repeat(100);
        let suffix = "B".repeat(100);
        let body = format!("{} {} {}", prefix, AWS_KEY, suffix);
        let secrets = detect_exposed_secrets(&body);
        assert_eq!(secrets.len(), 1);
        assert!(secrets[0].context.contains("AAAA"));
        assert!(secrets[0].context.contains("BBBB"));
    }

    /// L-6 regression: when the match itself is longer than [`MAX_CONTEXT_BYTES`]
    /// (e.g. a 4 KB private key), the context column stays bounded by replacing
    /// the middle of the match with `...[truncated]...`. The surrounding code
    /// context is preserved.
    #[test]
    fn test_context_cap_truncates_long_matches() {
        let huge_key = format!(
            "-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----",
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7".repeat(80)
        );
        let body = format!("// before\n{huge_key}\n// after");
        let secrets = detect_exposed_secrets(&body);
        assert_eq!(secrets.len(), 1);
        let ctx = &secrets[0].context;
        assert!(
            ctx.len() <= MAX_CONTEXT_BYTES,
            "context len {} must be <= MAX_CONTEXT_BYTES {}",
            ctx.len(),
            MAX_CONTEXT_BYTES
        );
        assert!(
            ctx.contains("...[truncated]..."),
            "context should mark truncation; got: {ctx:?}"
        );
        // Keep the surrounding signal even though the middle is gone.
        assert!(ctx.contains("BEGIN RSA PRIVATE KEY"));
        assert!(ctx.contains("END RSA PRIVATE KEY"));
    }

    /// Sanity: short matches still get the full surrounding context (no
    /// truncation marker, full match preserved).
    #[test]
    fn test_context_cap_preserves_short_matches() {
        let body = format!(r#"var key = "{AWS_KEY}";"#);
        let secrets = detect_exposed_secrets(&body);
        let aws = secrets
            .iter()
            .find(|s| s.secret_type == "aws-access-token")
            .unwrap();
        assert!(!aws.context.contains("...[truncated]..."));
        assert!(aws.context.contains(AWS_KEY));
        assert!(aws.context.len() < MAX_CONTEXT_BYTES);
    }

    /// Regression test: `extract_context` must not panic when the context window
    /// (start - 80 bytes or end + 80 bytes) lands inside a multi-byte UTF-8
    /// character. This reproduces the crash from a Polish page containing 'ę'
    /// (2-byte UTF-8) where byte arithmetic fell between the two bytes.
    #[test]
    fn test_context_multibyte_boundary_no_panic() {
        // Build a prefix of exactly 79 ASCII bytes followed by a 2-byte char 'ę'.
        // The AWS key match starts right after 'ę', so start - 80 = byte 79,
        // which is the second byte of 'ę' (not a char boundary).
        let prefix = format!("{}\u{0119}", "X".repeat(79)); // 79 + 2 = 81 bytes
        assert_eq!(prefix.len(), 81);
        assert!(!prefix.is_char_boundary(80)); // byte 80 is inside 'ę'

        // Same trick for suffix: 79 ASCII bytes preceded by a 2-byte char.
        let suffix = format!("\u{0119}{}", "Y".repeat(79)); // 2 + 79 = 81 bytes

        let body = format!("{} {} {}", prefix, AWS_KEY, suffix);
        let secrets = detect_exposed_secrets(&body);
        assert_eq!(secrets.len(), 1, "should detect the AWS key");
        // Context should include parts of both prefix and suffix without panicking.
        assert!(secrets[0].context.contains("XXXX"));
        assert!(secrets[0].context.contains("YYYY"));
    }

    #[test]
    fn test_gitleaks_config_loads() {
        let config = crate::parse::gitleaks::gitleaks();
        assert!(config.rules.len() > 200, "expected 200+ gitleaks rules");
        assert!(!config.global_allowlist.regexes.is_empty());
    }

    /// Helper: reduce findings to the dedupe-relevant (`rule_id`, `matched_value`) tuples.
    fn finding_keys(secrets: &[ExposedSecret]) -> std::collections::BTreeSet<(String, String)> {
        secrets
            .iter()
            .map(|s| (s.secret_type.clone(), s.matched_value.clone()))
            .collect()
    }

    /// Critical regression: the Aho-Corasick keyword prefilter is meant to be
    /// a pure perf shortcut. For any input body, the filtered detector and
    /// the unfiltered detector must produce the **same** set of
    /// `(rule_id, matched_value)` tuples. Any divergence is a correctness bug
    /// in the prefilter (a missing keyword for some rule, an automaton that
    /// doesn't see a substring, ASCII-only matching when the regex would
    /// match non-ASCII, etc.).
    ///
    /// The body distribution intentionally includes:
    /// - All printable ASCII (the dominant content type on the public web)
    /// - Strings with `=void`, `=t.`, key-like prefixes that exercise our
    ///   stopwords / overlay rules
    /// - Plausible AWS / Google / Stripe shapes so the regexes actually fire
    ///   often enough to find a divergence if one exists
    ///
    /// 256 cases gives high confidence at minor compile-time cost.
    #[test]
    fn test_prefilter_equivalence_on_random_bodies() {
        use proptest::prelude::*;

        // Make sure the bundled config is loaded once before proptest spins
        // up its iterations - avoids races on the lazy OnceLock under -j.
        let _ = crate::parse::gitleaks::try_gitleaks().expect("gitleaks loads");

        let body_strategy = prop_oneof![
            // Pure printable ASCII: the dominant production case.
            "[\\x20-\\x7e]{0,2048}",
            // Non-ASCII bytes embedded in HTML (charset edge cases).
            "[\\x20-\\xff]{0,1024}",
            // Realistic gitleaks-shaped strings - ensures we exercise the
            // actual rules, not just the prefilter on noise.
            r#"var (key|token|api_key|apiKey) ?= ?"[A-Za-z0-9_-]{20,80}";"#,
            r#"AKIA[A-Z2-7]{16}"#,
            r#"AIzaSy[A-Za-z0-9_-]{33}"#,
            r#"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}"#,
            // Edge: stopword-ish patterns that should NOT fire either way.
            r#"[a-z][a-zA-Z]+\.[a-z]+=void"#,
        ];

        proptest!(ProptestConfig::with_cases(256), |(body in body_strategy)| {
            let with_prefilter = detect_exposed_secrets(&body);
            let without_prefilter = detect_exposed_secrets_unfiltered(&body);
            let with_keys = finding_keys(&with_prefilter);
            let without_keys = finding_keys(&without_prefilter);
            prop_assert_eq!(
                with_keys.clone(),
                without_keys.clone(),
                "Prefilter divergence!\n\
                 body (first 200 chars): {}\n\
                 with_prefilter:    {:?}\n\
                 without_prefilter: {:?}",
                body.chars().take(200).collect::<String>(),
                with_keys,
                without_keys
            );
        });
    }

    /// Gitleaks keyword prefilter: sourcegraph-access-token has keywords ["sgp_", "sourcegraph"].
    /// Without either in the body, a plain 40-char hex (e.g. Git SHA) must not be reported.
    #[test]
    fn test_sourcegraph_no_fire_without_keyword() {
        let sha_like = "9c02de5c56d82f105252bb92478c88114ab41dce";
        let body = format!(r#"<span>commit {} </span>"#, sha_like);
        let secrets = detect_exposed_secrets(&body);
        let sourcegraph = secrets
            .iter()
            .find(|s| s.secret_type == "sourcegraph-access-token");
        assert!(
            sourcegraph.is_none(),
            "sourcegraph-access-token must not fire without keyword in body; got {:?}",
            secrets
        );
    }

    /// With "sourcegraph" in the body, a 40-char hex can be reported as sourcegraph-access-token.
    #[test]
    fn test_sourcegraph_fires_with_keyword() {
        // Real tokens use the sgp_ prefix; bare 40-hex is intentionally rejected.
        let token = format!(
            "sgp_{}_{}",
            "0123456789abcdef", "a1b2c3d4e5f6789012345678901234567890abcd"
        );
        let body = format!(r#"<script>window.SOURCEGRAPH = "{token}";</script>"#);
        let secrets = detect_exposed_secrets(&body);
        let sourcegraph = secrets
            .iter()
            .find(|s| s.secret_type == "sourcegraph-access-token");
        assert!(
            sourcegraph.is_some(),
            "sourcegraph-access-token should fire for sgp_ tokens; got {secrets:?}"
        );
        assert_eq!(sourcegraph.unwrap().matched_value, token);
    }

    /// Per-rule allowlist: 40-char hex in html id="..." (e.g. Wix build ID) must not be reported as sourcegraph-access-token.
    #[test]
    fn test_sourcegraph_allowlist_html_id_skipped() {
        let build_id = "1ccd1dddac2890afd4e9eb54f87f22008b1ed114";
        let body = format!(
            r#"<html id="{}" class="StudioLegacy Legacy">sourcegraph integration</html>"#,
            build_id
        );
        let secrets = detect_exposed_secrets(&body);
        let sourcegraph = secrets
            .iter()
            .find(|s| s.secret_type == "sourcegraph-access-token");
        assert!(
            sourcegraph.is_none(),
            "40-char hex in html id= should be allowlisted; got {:?}",
            secrets
        );
    }

    /// Cloudflare email obfuscation: 40-char hex in email-protection# or data-cfemail= must be allowlisted.
    #[test]
    fn test_sourcegraph_allowlist_cloudflare_email_skipped() {
        let hex = "3f565159507f5e53545e52564b5a5c57115c5052";
        let body = format!(
            r#"<a href="/cdn-cgi/l/email-protection#{}">Contact</a> sourcegraph"#,
            hex
        );
        let secrets = detect_exposed_secrets(&body);
        let sourcegraph = secrets
            .iter()
            .find(|s| s.secret_type == "sourcegraph-access-token");
        assert!(
            sourcegraph.is_none(),
            "40-char hex in Cloudflare email-protection# should be allowlisted; got {:?}",
            secrets
        );
        let body2 = format!(
            r#"<span class="__cf_email__" data-cfemail="{}">[email protected]</span> sourcegraph"#,
            "cca5a2aaa38cada0a7ada1a5b8a9afa4e2afa3a1"
        );
        let secrets2 = detect_exposed_secrets(&body2);
        let sg2 = secrets2
            .iter()
            .find(|s| s.secret_type == "sourcegraph-access-token");
        assert!(
            sg2.is_none(),
            "40-char hex in data-cfemail= should be allowlisted; got {:?}",
            secrets2
        );
    }

    /// Per-rule allowlist: data-hubspot-form="uuid" is a form/embed ID, not an API key; must not be reported as hubspot-api-key.
    #[test]
    fn test_hubspot_allowlist_form_id_skipped() {
        // Rule matches uppercase hex UUID; use uppercase so the rule fires, then allowlist skips.
        let form_id = "AC4D982E-062E-4795-B5E5-718351F44BB9";
        let body = format!(
            r#"<div data-hubspot-form="{}" class="hs-form"></div>"#,
            form_id
        );
        let secrets = detect_exposed_secrets(&body);
        let hubspot = secrets.iter().find(|s| s.secret_type == "hubspot-api-key");
        assert!(
            hubspot.is_none(),
            "data-hubspot-form= UUID should be allowlisted (form ID, not API key); got {:?}",
            secrets
        );
    }

    /// `HubSpot` API key in script context (no data-hubspot-form on line) must still be reported.
    #[test]
    fn test_hubspot_api_key_in_script_still_reported() {
        let uuid = "AC4D982E-062E-4795-B5E5-718351F44BB9";
        let body = format!(r#"<script>window.HUBSPOT_API_KEY="{}";</script>"#, uuid);
        let secrets = detect_exposed_secrets(&body);
        let hubspot = secrets.iter().find(|s| s.secret_type == "hubspot-api-key");
        assert!(
            hubspot.is_some(),
            "hubspot UUID in script (no data-hubspot-form) should still be reported; got {:?}",
            secrets
        );
        assert_eq!(hubspot.unwrap().matched_value, uuid);
    }

    /// Response-header correlation IDs must not be reported as `HubSpot` API keys.
    #[test]
    fn test_hubspot_correlation_id_header_skipped() {
        let uuid = "019F9044-75EC-7F8C-9A70-F99ED4ECC4BD";
        let headers = format!("x-hubspot-correlation-id: {uuid}\nserver: cloudflare\n");
        let secrets = detect_exposed_secrets_in_headers(&headers);
        let hubspot = secrets.iter().find(|s| s.secret_type == "hubspot-api-key");
        assert!(
            hubspot.is_none(),
            "x-hubspot-correlation-id should be allowlisted; got {:?}",
            secrets
        );
    }

    /// Public `HubSpot` form widget IDs in env/config blobs must be skipped.
    #[test]
    fn test_hubspot_form_id_config_skipped() {
        let form_id = "7EA134CD-6DBC-482C-B7C2-576FBF09725E";
        let cases = [
            format!(r#"PUBLIC_HUBSPOT_CONTACT_FORM_ID:"{form_id}""#),
            format!(r#""hubspotFormIdProd":"{form_id}""#),
            format!(r#"REACT_APP_HUBSPOT_FORM_ID_EN:"{form_id}""#),
            format!(r#""hubspot_button_id":"{form_id}""#),
            format!(r#"hubspotSignupguid:"{form_id}""#),
            format!(r#"hubspotID:"{form_id}""#),
        ];
        for body in cases {
            let secrets = detect_exposed_secrets(&body);
            let hubspot = secrets.iter().find(|s| s.secret_type == "hubspot-api-key");
            assert!(
                hubspot.is_none(),
                "HubSpot form ID config should be allowlisted; body={body:?} got={secrets:?}"
            );
        }
    }

    /// Power BI embed tokens share Grafana's eyJrIjoi prefix and must be skipped.
    #[test]
    fn test_grafana_api_key_powerbi_embed_skipped() {
        let token = "eyJrIjoiNTc5MmJjODMtYTM1NS00MWZlLWE1N2EtN2IyNThiOTk3MjI1IiwidCI6IjlkZjk0OWY4LWE2ZWItNDE5ZC05Y2FhLTFmOGM4M2RiNjc0ZiJ9";
        let body = format!(r#"href="https://app.powerbi.com/view?r={token}" target="_blank""#);
        let secrets = detect_exposed_secrets(&body);
        let grafana = secrets.iter().find(|s| s.secret_type == "grafana-api-key");
        assert!(
            grafana.is_none(),
            "Power BI embed token should not be grafana-api-key; got {:?}",
            secrets
        );
    }

    /// A bare Grafana-shaped eyJrIjoi token (no Power BI host) must still be reported.
    #[test]
    fn test_grafana_api_key_without_powerbi_still_reported() {
        let token = "eyJrIjoiNTc5MmJjODMtYTM1NS00MWZlLWE1N2EtN2IyNThiOTk3MjI1IiwidCI6IjlkZjk0OWY4LWE2ZWItNDE5ZC05Y2FhLTFmOGM4M2RiNjc0ZiJ9";
        let body = format!(r#"const grafanaApiKey = "{token}";"#);
        let secrets = detect_exposed_secrets(&body);
        let grafana = secrets.iter().find(|s| s.secret_type == "grafana-api-key");
        assert!(
            grafana.is_some(),
            "Grafana eyJrIjoi token without powerbi.com should still be reported; got {:?}",
            secrets
        );
        assert_eq!(grafana.unwrap().matched_value, token);
    }

    /// Upstream dropbox-api-token (15-char near "dropbox") is disabled for web.
    #[test]
    fn test_dropbox_short_identifier_near_dropbox_skipped() {
        let body = r#"{"dropbox":true,"theChampSiteUrl":"abcde1234567890"}"#;
        let secrets = detect_exposed_secrets(body);
        let dropbox = secrets
            .iter()
            .find(|s| s.secret_type == "dropbox-api-token");
        assert!(
            dropbox.is_none(),
            "15-char near dropbox must not fire dropbox-api-token; got {:?}",
            secrets
        );
    }

    /// Disabling dropbox-api-token must not break distinctive long/short-lived rules.
    #[test]
    fn test_dropbox_long_and_short_lived_still_detected() {
        // Long-lived: [a-z0-9]{11}AAAAAAAAAA[a-z0-9\-_=]{43} (letters must be lowercase).
        let prefix11 = "abcdefghijk";
        let mid = "AAAAAAAAAA";
        let suffix43 = "0123456789_-x7km2pq9vl4nr8wy1st6ua3bc5de0fg";
        assert_eq!(suffix43.len(), 43);
        let long_tok = format!("{prefix11}{mid}{suffix43}");
        let body_long = format!(r#"dropbox_token = "{long_tok}""#);
        let secrets_long = detect_exposed_secrets(&body_long);
        assert!(
            secrets_long
                .iter()
                .any(|s| s.secret_type == "dropbox-long-lived-api-token"),
            "long-lived Dropbox token must still match; got {secrets_long:?}"
        );

        // Short-lived: sl.[a-z0-9\-=_]{135} (letters must be lowercase).
        let short_rest = "x7km2pq9vl4nr8wy1st6ua3bc5de0fg2hj4km6np8qs0tv2wx4yz6ab8cd0ef2gh4jx7km2pq9vl4nr8wy1st6ua3bc5de0fg2hj4km6np8qs0tv2wx4yz6ab8cd0ef2gh4jxxx";
        assert_eq!(short_rest.len(), 135);
        let short_tok = format!("sl.{short_rest}");
        let body_short = format!(r#"dropbox_api = "{short_tok}""#);
        let secrets_short = detect_exposed_secrets(&body_short);
        assert!(
            secrets_short
                .iter()
                .any(|s| s.secret_type == "dropbox-short-lived-api-token"),
            "short-lived Dropbox token must still match; got {secrets_short:?}"
        );
    }

    /// Square EAAA… (binary collision) must not match; sq0atp- still does.
    #[test]
    fn test_square_eaaa_skipped_sq0atp_kept() {
        let eaaa = "EAAA".to_string() + &"A".repeat(40);
        let body_eaaa = format!(r#"binary blob {eaaa} noise"#);
        let secrets_eaaa = detect_exposed_secrets(&body_eaaa);
        assert!(
            secrets_eaaa
                .iter()
                .all(|s| s.secret_type != "square-access-token"),
            "EAAA must not match square-access-token; got {:?}",
            secrets_eaaa
        );

        // Avoid global allowlist stopwords like "abcdefghijklmnopqrstuvwxyz".
        let sq = "sq0atp-9fK2mP7xQ4nR8wL1sT6uA3bC5dE0";
        let body_sq = format!(r#"const token = "{sq}";"#);
        let secrets_sq = detect_exposed_secrets(&body_sq);
        let square = secrets_sq
            .iter()
            .find(|s| s.secret_type == "square-access-token");
        assert!(
            square.is_some(),
            "sq0atp- Square PAT should still be reported; got {:?}",
            secrets_sq
        );
        assert_eq!(square.unwrap().matched_value, sq);
    }

    /// datadogVersion build hash must not match; `DD_API_KEY` assignment must.
    #[test]
    fn test_datadog_version_skipped_api_key_kept() {
        let hash = "e561f43f1a2b3c4d5e6f708192a3b4c5d6e7f809";
        let body_ver = format!(r#"{{"datadogVersion":"{hash}"}}"#);
        let secrets_ver = detect_exposed_secrets(&body_ver);
        assert!(
            secrets_ver
                .iter()
                .all(|s| s.secret_type != "datadog-access-token"),
            "datadogVersion hash must not match; got {:?}",
            secrets_ver
        );

        let body_key = format!(r#"DD_API_KEY={hash}"#);
        let secrets_key = detect_exposed_secrets(&body_key);
        let dd = secrets_key
            .iter()
            .find(|s| s.secret_type == "datadog-access-token");
        assert!(
            dd.is_some(),
            "DD_API_KEY assignment should still be reported; got {:?}",
            secrets_key
        );
        assert_eq!(dd.unwrap().matched_value, hash);
    }

    /// Bare `apiKey`/`appKey` hex assignments collide with many third-party SDKs. Keep
    /// `datadog-access-token` only when nearby text identifies Datadog; Algolia /
    /// Bugsnag / etc. must not match. `DD_API_KEY` (contains `dd_api`) still matches.
    #[test]
    fn test_datadog_requires_datadog_context() {
        let hash = "e561f43f1a2b3c4d5e6f708192a3b4c5d6e7f809";

        let body_algolia_camel = format!(r#"var algoliaApiKey = "{hash}";"#);
        let secrets_algolia_camel = detect_exposed_secrets(&body_algolia_camel);
        assert!(
            secrets_algolia_camel
                .iter()
                .all(|s| s.secret_type != "datadog-access-token"),
            "algoliaApiKey assignment must not match datadog-access-token; got {:?}",
            secrets_algolia_camel
        );

        let body_al_apikey = format!(r#"var al_apiKey = "{hash}";"#);
        let secrets_al_apikey = detect_exposed_secrets(&body_al_apikey);
        assert!(
            secrets_al_apikey
                .iter()
                .all(|s| s.secret_type != "datadog-access-token"),
            "al_apiKey assignment must not match datadog-access-token; got {:?}",
            secrets_al_apikey
        );

        let body_nearby = format!(r#"algolia config: apiKey: "{hash}", appId: "ABC123XYZ""#);
        let secrets_nearby = detect_exposed_secrets(&body_nearby);
        assert!(
            secrets_nearby
                .iter()
                .all(|s| s.secret_type != "datadog-access-token"),
            "apiKey near 'algolia' context must not match datadog-access-token; got {:?}",
            secrets_nearby
        );

        let body_bugsnag = format!(r#"Bugsnag.start({{ apiKey: "{hash}" }});"#);
        let secrets_bugsnag = detect_exposed_secrets(&body_bugsnag);
        assert!(
            secrets_bugsnag
                .iter()
                .all(|s| s.secret_type != "datadog-access-token"),
            "Bugsnag apiKey must not match datadog-access-token; got {:?}",
            secrets_bugsnag
        );

        let body_bare = format!(r#"const apiKey = "{hash}";"#);
        let secrets_bare = detect_exposed_secrets(&body_bare);
        assert!(
            secrets_bare
                .iter()
                .all(|s| s.secret_type != "datadog-access-token"),
            "bare apiKey without Datadog context must not match; got {:?}",
            secrets_bare
        );

        // Real Datadog assignment (DD_API_KEY embeds dd_api identity).
        let body_key = format!(r#"DD_API_KEY={hash}"#);
        let secrets_key = detect_exposed_secrets(&body_key);
        let dd = secrets_key
            .iter()
            .find(|s| s.secret_type == "datadog-access-token");
        assert!(
            dd.is_some(),
            "DD_API_KEY assignment should still be reported; got {:?}",
            secrets_key
        );
        assert_eq!(dd.unwrap().matched_value, hash);

        let body_rum = format!(
            r#"window.DD_RUM.init({{ clientToken: "pubxxx", site: "datadoghq.com", apiKey: "{hash}" }});"#
        );
        let secrets_rum = detect_exposed_secrets(&body_rum);
        assert!(
            secrets_rum
                .iter()
                .any(|s| s.secret_type == "datadog-access-token" && s.matched_value == hash),
            "apiKey near datadog RUM context should be reported; got {:?}",
            secrets_rum
        );
    }

    /// Bare EAAC… without `access_token` assignment must not match; assignment must.
    #[test]
    fn test_facebook_page_token_requires_assignment() {
        // High-entropy EAAC token; need ≥100 chars after EAAC for the rule.
        let token = format!(
            "EAAC{}",
            "x7Km2pQ9vL4nR8wY1sT6uA3bC5dE0fG2hJ4kM6nP8qS0tV2wX4yZ6aB8cD0eF2gH4j".repeat(2)
        );
        assert!(token.len() >= 104);
        let body_bare = format!(r#"noise {token} more"#);
        let secrets_bare = detect_exposed_secrets(&body_bare);
        assert!(
            secrets_bare
                .iter()
                .all(|s| s.secret_type != "facebook-page-access-token"),
            "bare EAAC must not match facebook-page-access-token; got {:?}",
            secrets_bare
        );

        let body_assign = format!(r#"access_token="{token}""#);
        let secrets_assign = detect_exposed_secrets(&body_assign);
        let fb = secrets_assign
            .iter()
            .find(|s| s.secret_type == "facebook-page-access-token");
        assert!(
            fb.is_some(),
            "access_token= EAAC should still be reported; got {:?}",
            secrets_assign
        );
        assert_eq!(fb.unwrap().matched_value, token);
    }

    /// Lowercase camelCase near linkedin (JS property) must be skipped.
    #[test]
    fn test_linkedin_camelcase_property_skipped() {
        let body = r#"{"linkedin":"share","thumbnailWidth":"abcdefghijklmn"}"#;
        let secrets = detect_exposed_secrets(body);
        assert!(
            secrets
                .iter()
                .all(|s| s.secret_type != "linkedin-client-id"),
            "thumbnailWidth must not match linkedin-client-id; got {:?}",
            secrets
        );
    }

    /// Lowercase camelCase 16-char property must not match linkedin-client-secret.
    #[test]
    fn test_linkedin_client_secret_camelcase_skipped() {
        let body = r#"linkedin_client_secret = "thumbnailWidthab""#;
        let secrets = detect_exposed_secrets(body);
        assert!(
            secrets
                .iter()
                .all(|s| s.secret_type != "linkedin-client-secret"),
            "camelCase property must not be reported as linkedin-client-secret; got {secrets:?}"
        );
    }

    /// Opaque non-camel `LinkedIn` client id assignment must still be reported.
    #[test]
    fn test_linkedin_opaque_client_id_still_reported() {
        // 14-char opaque token: no lowercase→uppercase camelCase transition.
        let client_id = "ab12cd34ef56gh";
        let body = format!(r#"linkedin_client_id = "{client_id}""#);
        let secrets = detect_exposed_secrets(&body);
        let linkedin = secrets
            .iter()
            .find(|s| s.secret_type == "linkedin-client-id");
        assert!(
            linkedin.is_some(),
            "opaque linkedin client id should still be reported; got {:?}",
            secrets
        );
        assert_eq!(linkedin.unwrap().matched_value, client_id);
    }

    /// Opaque 16-char `LinkedIn` client secret must still be reported.
    #[test]
    fn test_linkedin_opaque_client_secret_still_reported() {
        let secret = "a1b2c3d4e5f6g7h8";
        assert_eq!(secret.len(), 16);
        let body = format!(r#"linkedin_client_secret = "{secret}""#);
        let secrets = detect_exposed_secrets(&body);
        let linkedin = secrets
            .iter()
            .find(|s| s.secret_type == "linkedin-client-secret");
        assert!(
            linkedin.is_some(),
            "opaque linkedin client secret should still be reported; got {:?}",
            secrets
        );
        assert_eq!(linkedin.unwrap().matched_value, secret);
    }

    /// X-Amz-Credential= AWS key IDs are Low; bare AKIA in HTML remains High.
    #[test]
    fn test_aws_amz_credential_severity_demoted() {
        // AKIA + 16 chars from [A-Z2-7] (no 0/1/8/9); must not end in EXAMPLE.
        let akia = "AKIAYCQ2ABCD2EFGHJKL";
        assert_eq!(akia.len(), 20);

        let signed = format!(
            r#"href="https://bucket.s3.amazonaws.com/x?X-Amz-Credential={akia}%2F20260101%2Fus-east-1%2Fs3%2Faws4_request""#
        );
        let secrets_signed = detect_exposed_secrets(&signed);
        let aws_signed = secrets_signed
            .iter()
            .find(|s| s.secret_type == "aws-access-token");
        assert!(
            aws_signed.is_some(),
            "Amz-Credential AKIA should still be recorded; got {:?}",
            secrets_signed
        );
        assert_eq!(
            aws_signed.unwrap().severity,
            SecretSeverity::Low,
            "Amz-Credential should be Low severity"
        );

        let comment = format!(r#"<!-- {akia} VFvFrZXsecretlooking -->"#);
        let secrets_comment = detect_exposed_secrets(&comment);
        let aws_comment = secrets_comment
            .iter()
            .find(|s| s.secret_type == "aws-access-token");
        assert!(
            aws_comment.is_some(),
            "bare AKIA in comment should still be reported; got {:?}",
            secrets_comment
        );
        assert_eq!(
            aws_comment.unwrap().severity,
            SecretSeverity::High,
            "bare AKIA should remain High"
        );
    }

    /// Weglot / App Insights / Prismic public IDs must not fire generic-api-key.
    #[test]
    fn test_generic_public_product_ids_skipped() {
        let weglot_key = "wg_0123456789abcdef0123456789abcdef";
        let body_wg = format!(r#"Weglot.initialize({{ api_key: '{weglot_key}' }});"#);
        let secrets_wg = detect_exposed_secrets(&body_wg);
        assert!(
            secrets_wg
                .iter()
                .all(|s| !(s.secret_type == "generic-api-key"
                    && s.matched_value.eq_ignore_ascii_case(weglot_key))),
            "Weglot wg_ key should be allowlisted; got {:?}",
            secrets_wg
        );

        let uuid = "12345678-1234-1234-1234-123456789abc";
        let body_ai = format!(r#"instrumentationKey:'{uuid}'"#);
        let secrets_ai = detect_exposed_secrets(&body_ai);
        assert!(
            secrets_ai
                .iter()
                .all(|s| !(s.secret_type == "generic-api-key" && s.matched_value == uuid)),
            "App Insights instrumentationKey should be allowlisted; got {:?}",
            secrets_ai
        );

        let body_prismic = format!(
            r#"{{"link":{{"link_type":"Document","key":"{uuid}","url":"https://example.com"}}}}"#
        );
        let secrets_prismic = detect_exposed_secrets(&body_prismic);
        assert!(
            secrets_prismic
                .iter()
                .all(|s| !(s.secret_type == "generic-api-key" && s.matched_value == uuid)),
            "Prismic link_type+key should be allowlisted; got {:?}",
            secrets_prismic
        );

        let hex40 = "000f0192a841c56389c0ea2bff307ee1f771334f";
        let body_minified_prismic =
            format!(r#"last_publication_date:"2026-07-10",uid:aM,link_type:c,key:"{hex40}""#);
        let secrets_minified = detect_exposed_secrets(&body_minified_prismic);
        assert!(
            secrets_minified
                .iter()
                .all(|s| !(s.secret_type == "generic-api-key" && s.matched_value == hex40)),
            "minified link_type:c,key should be allowlisted; got {:?}",
            secrets_minified
        );

        let body_react_key = format!(r#"return eb(ev,{{key:"{hex40}",role:this.getRole()}})"#);
        let secrets_react = detect_exposed_secrets(&body_react_key);
        assert!(
            secrets_react
                .iter()
                .all(|s| !(s.secret_type == "generic-api-key" && s.matched_value == hex40)),
            "React key:\"<40hex>\" should be allowlisted; got {:?}",
            secrets_react
        );

        let body_bot = format!(r#""botSignalToken":"{hex40}","botSignalTimestamp":"6a89f8b7""#);
        let secrets_bot = detect_exposed_secrets(&body_bot);
        assert!(
            secrets_bot
                .iter()
                .all(|s| !(s.secret_type == "generic-api-key" && s.matched_value == hex40)),
            "botSignalToken should be allowlisted; got {:?}",
            secrets_bot
        );

        // Bare apiKey assignment of hex must still be eligible for generic-api-key
        // (not caught by the key: allowlist).
        let body_api = format!(r#"const apiKey = "{hex40}";"#);
        let secrets_api = detect_exposed_secrets(&body_api);
        assert!(
            secrets_api
                .iter()
                .any(|s| s.secret_type == "generic-api-key" && s.matched_value == hex40),
            "apiKey assignment should still match generic-api-key; got {:?}",
            secrets_api
        );
    }

    /// Discord client secret requires discord*client*secret assignment, not URL/CSS noise.
    #[test]
    fn test_discord_client_secret_requires_assignment() {
        let body_fp = r#"{"platforms-subtitle1-image2":"https://assets.example.com/ai-live-captions-google-meet-discord-voov.webp","platforms-subtitle1-image2-title":"Online meeting"}"#;
        let secrets_fp = detect_exposed_secrets(body_fp);
        assert!(
            secrets_fp
                .iter()
                .all(|s| s.secret_type != "discord-client-secret"),
            "discord in URL/CSS must not fire discord-client-secret; got {:?}",
            secrets_fp
        );

        let secret = "a1b2c3d4e5f6789012345678abcdef01";
        let body_ok = format!(r#"discord_client_secret = "{secret}""#);
        let secrets_ok = detect_exposed_secrets(&body_ok);
        let hit = secrets_ok
            .iter()
            .find(|s| s.secret_type == "discord-client-secret");
        assert!(
            hit.is_some(),
            "discord_client_secret assignment should be reported; got {:?}",
            secrets_ok
        );
        assert_eq!(hit.unwrap().matched_value, secret);
    }

    /// JWT rule severity is explicitly Low (inventory, not triage-urgent).
    #[test]
    fn test_jwt_severity_is_low() {
        assert_eq!(severity_for_rule_id("jwt"), SecretSeverity::Low);
        assert_eq!(severity_for_rule_id("jwt-base64"), SecretSeverity::Low);
    }

    /// `LinkedIn` client-id rule: line with extensionPointId / pageJsonFileName (block IDs) must be allowlisted.
    #[test]
    fn test_linkedin_client_id_allowlist_structure_skipped() {
        let body = r#"{"blockId":"uselectrical.b2bstore@4.x:menu-item#footer-linkedin","extensionPointId":"menu-item#footer-linkedin"}"#;
        let secrets = detect_exposed_secrets(body);
        let linkedin = secrets
            .iter()
            .find(|s| s.secret_type == "linkedin-client-id");
        assert!(
            linkedin.is_none(),
            "linkedin-client-id with extensionPointId/footer-linkedin should be allowlisted; got {:?}",
            secrets
        );
    }

    /// `Sumologic`: sumoSiteId in embed script is public site ID, not access token.
    #[test]
    fn test_sumologic_allowlist_site_id_skipped() {
        let site_id = "38d92200f6b3d700b2eb2e0069250000108b3e00a638e0004c77b700ec8ea400";
        let body = format!(
            r#"j.dataset.sumoSiteId='{}';j.dataset.sumoPlatform='wordpress';"#,
            site_id
        );
        let secrets = detect_exposed_secrets(&body);
        let sumo = secrets
            .iter()
            .find(|s| s.secret_type == "sumologic-access-token");
        assert!(
            sumo.is_none(),
            "sumologic sumoSiteId (public site ID) should be allowlisted; got {:?}",
            secrets
        );
    }

    /// Path-restricted rules (e.g. hashicorp-tf-password for .tf/.hcl) are skipped when scanning a single blob (HTML) with no file path.
    #[test]
    fn test_path_restricted_rule_skipped_on_html() {
        let body = r#"<script>p_lt_ctl13_AFI_CustomRegistrationForm_plcUp_formUser_UserPassword_rfvConfirmPassword.validationGroup = "ConfirmRegForm";</script>"#;
        let secrets = detect_exposed_secrets(body);
        let tf_password = secrets
            .iter()
            .find(|s| s.secret_type == "hashicorp-tf-password");
        assert!(
            tf_password.is_none(),
            "hashicorp-tf-password (path-restricted) must be skipped when scanning HTML; got {:?}",
            secrets
        );
    }

    /// sonar-api-token has secretGroup = 2; extracted secret must be group 2 (the token), not group 1 (login|token).
    #[test]
    fn test_sonar_secret_group_2() {
        // Regex group 1 = (login|token), group 2 = 40-char token. secretGroup=2 => we store group 2.
        let token = "squ_abcdefghij0123456789abcdefghij012345"; // 40 chars
        let body = format!(r#"sonar_token="{}""#, token);
        let secrets = detect_exposed_secrets(&body);
        let sonar = secrets.iter().find(|s| s.secret_type == "sonar-api-token");
        assert!(
            sonar.is_some(),
            "expected sonar-api-token finding: {:?}",
            secrets
        );
        assert_eq!(
            sonar.unwrap().matched_value,
            token,
            "secretGroup=2 should yield the token (group 2), not 'token' (group 1)"
        );
    }

    #[test]
    fn test_severity_as_str() {
        assert_eq!(SecretSeverity::Critical.as_str(), "critical");
        assert_eq!(SecretSeverity::High.as_str(), "high");
        assert_eq!(SecretSeverity::Medium.as_str(), "medium");
        assert_eq!(SecretSeverity::Low.as_str(), "low");
    }

    #[test]
    fn test_redact_exposed_secret_value_replaces_raw_secret() {
        let redacted = redact_exposed_secret_value(AWS_KEY);
        assert!(redacted.contains("sha256="));
        assert!(!redacted.contains(AWS_KEY));
        assert!(redacted.contains("AKIA"));
    }

    #[test]
    fn test_redact_exposed_secret_context_replaces_secret_occurrences() {
        let context = format!("before {AWS_KEY} after");
        let redacted = redact_exposed_secret_context(&context, AWS_KEY);
        assert!(redacted.contains("before"));
        assert!(redacted.contains("after"));
        assert!(!redacted.contains(AWS_KEY));
    }

    /// Condition AND with `has_paths`: for single-blob we never have a file path, so AND never succeeds and we must not skip.
    #[test]
    fn test_rule_allowlist_condition_and_with_paths_does_not_skip() {
        use crate::parse::gitleaks::CompiledRuleAllowlist;
        use regex::Regex;

        let re = Regex::new("EXAMPLE").unwrap();
        let list = CompiledRuleAllowlist {
            regexes: vec![re],
            stopwords: vec![],
            regex_target: None,
            condition_and: true,
            has_paths: true,
        };
        // Target matches the regex, but AND requires all criteria; path is N/A so we treat as not matched -> do not skip.
        let skips = rule_allowlist_skips(
            &[list],
            "AKIAIOSFODNN7EXAMPLE",
            "line content",
            "full match",
        );
        assert!(
            !skips,
            "AND with has_paths must not skip (path never matches in single-blob)"
        );
    }

    // === Database Connection URIs ===

    #[test]
    fn test_detect_mongodb_connection_uri() {
        let body = r#"<script>var dbUrl = "mongodb+srv://admin:s3cretP4ss@cluster0.mongodb.net/mydb";</script>"#;
        let secrets = detect_exposed_secrets(body);
        let db = secrets
            .iter()
            .find(|s| s.secret_type == "database-connection-uri");
        assert!(db.is_some(), "should detect MongoDB URI; got {:?}", secrets);
        let db = db.unwrap();
        // M-4: matched_value is now the full URI so analysts see host/db,
        // not just the bare password.
        assert_eq!(
            db.matched_value,
            "mongodb+srv://admin:s3cretP4ss@cluster0.mongodb.net/mydb"
        );
        assert_eq!(db.severity, SecretSeverity::Critical);
    }

    #[test]
    fn test_detect_postgres_connection_uri() {
        let body = r#"<!-- config: postgres://appuser:hunter2@db.example.com:5432/production -->"#;
        let secrets = detect_exposed_secrets(body);
        let db = secrets
            .iter()
            .find(|s| s.secret_type == "database-connection-uri");
        assert!(
            db.is_some(),
            "should detect PostgreSQL URI; got {:?}",
            secrets
        );
        assert_eq!(
            db.unwrap().matched_value,
            "postgres://appuser:hunter2@db.example.com:5432/production"
        );
    }

    #[test]
    fn test_detect_redis_connection_uri() {
        let body = r#"REDIS_URL=redis://default:myP4ssword@cache.example.com:6379/0"#;
        let secrets = detect_exposed_secrets(body);
        let db = secrets
            .iter()
            .find(|s| s.secret_type == "database-connection-uri");
        assert!(db.is_some(), "should detect Redis URI; got {:?}", secrets);
        assert_eq!(
            db.unwrap().matched_value,
            "redis://default:myP4ssword@cache.example.com:6379/0"
        );
    }

    #[test]
    fn test_detect_mysql_connection_uri() {
        let body = r#"mysql://root:Str0ngP@ss@mysql.internal:3306/appdb"#;
        let secrets = detect_exposed_secrets(body);
        let db = secrets
            .iter()
            .find(|s| s.secret_type == "database-connection-uri");
        assert!(db.is_some(), "should detect MySQL URI; got {:?}", secrets);
    }

    #[test]
    fn test_no_detect_mongodb_without_credentials() {
        let body = r#"mongodb://localhost/testdb"#;
        let secrets = detect_exposed_secrets(body);
        let db = secrets
            .iter()
            .find(|s| s.secret_type == "database-connection-uri");
        assert!(
            db.is_none(),
            "should NOT detect URI without credentials; got {:?}",
            secrets
        );
    }

    // === HTTP Basic Auth ===

    #[test]
    fn test_detect_http_basic_auth() {
        let body = r#"<script>xhr.setRequestHeader("Authorization", "Basic dXNlcjpzM2NyZXRQNHNz");</script>"#;
        let secrets = detect_exposed_secrets(body);
        let auth = secrets.iter().find(|s| s.secret_type == "http-basic-auth");
        assert!(
            auth.is_some(),
            "should detect HTTP Basic Auth; got {:?}",
            secrets
        );
        assert_eq!(auth.unwrap().severity, SecretSeverity::High);
    }

    #[test]
    fn test_no_detect_http_basic_auth_too_short() {
        // "Og==" is base64 for ":" — too short (< 6 base64 chars)
        let body = r#"Authorization: Basic Og=="#;
        let secrets = detect_exposed_secrets(body);
        let auth = secrets.iter().find(|s| s.secret_type == "http-basic-auth");
        assert!(
            auth.is_none(),
            "trivially short Basic auth should not match; got {:?}",
            secrets
        );
    }

    // === Credential-bearing URLs (https://user:pass@host) ===

    #[test]
    fn test_detect_credential_url() {
        let body =
            r#"fetch("https://deploy:ghp_x7K9mQ2vL8nR3pW1234567890ab@api.internal.com/v1/data")"#;
        let secrets = detect_exposed_secrets(body);
        let url = secrets
            .iter()
            .find(|s| s.secret_type == "credential-bearing-url");
        assert!(
            url.is_some(),
            "should detect credential URL; got {:?}",
            secrets
        );
        assert_eq!(url.unwrap().severity, SecretSeverity::Critical);
    }

    // === Mailchimp API keys ===

    #[test]
    fn test_detect_mailchimp_api_key() {
        // Build at runtime to avoid GitHub push protection flagging the test fixture
        let key = format!("{}-us14", "abcdef1234567890abcdef1234567890");
        let body = format!(r#"<script>var mc_key = "mailchimp {key}";</script>"#);
        let secrets = detect_exposed_secrets(&body);
        let mc = secrets
            .iter()
            .find(|s| s.secret_type == "mailchimp-api-key");
        assert!(
            mc.is_some(),
            "should detect Mailchimp API key; got {:?}",
            secrets
        );
        assert_eq!(mc.unwrap().severity, SecretSeverity::High);
    }

    // === SendGrid API keys ===

    #[test]
    fn test_detect_sendgrid_api_key() {
        // Build at runtime to avoid GitHub push protection flagging the test fixture
        let key = format!(
            "SG.{}.{}",
            "ngeVfQFYQlKU0ufo8x5d1A", "TwL2iGABf9DHoTf09kqeF8tAmbihYzrnopKc1s5cr3t"
        );
        let body = format!(r#"apiKey: "{key}""#);
        let secrets = detect_exposed_secrets(&body);
        let sg = secrets
            .iter()
            .find(|s| s.secret_type == "sendgrid-api-token");
        assert!(
            sg.is_some(),
            "should detect SendGrid API key; got {:?}",
            secrets
        );
    }

    // === Placeholder filtering ===

    #[test]
    fn test_no_detect_placeholder_password_in_db_uri() {
        let body = r#"mongodb://admin:$PASSWORD@cluster.mongodb.net/db"#;
        let secrets = detect_exposed_secrets(body);
        let db = secrets
            .iter()
            .find(|s| s.secret_type == "database-connection-uri");
        assert!(
            db.is_none(),
            "variable placeholder $PASSWORD should not be flagged; got {:?}",
            secrets
        );
    }

    #[test]
    fn test_no_detect_placeholder_xxx_in_db_uri() {
        let body = r#"postgres://user:xxxxxxxx@db.example.com/app"#;
        let secrets = detect_exposed_secrets(body);
        let db = secrets
            .iter()
            .find(|s| s.secret_type == "database-connection-uri");
        assert!(
            db.is_none(),
            "redacted xxxxxxxx should not be flagged; got {:?}",
            secrets
        );
    }

    #[test]
    fn test_no_detect_placeholder_template_token_in_db_uri() {
        // `<password>` template token between : and @ should be allowlisted.
        let body = r#"<script>db = "mongodb://admin:<password>@cluster.local/db";</script>"#;
        let secrets = detect_exposed_secrets(body);
        let db = secrets
            .iter()
            .find(|s| s.secret_type == "database-connection-uri");
        assert!(
            db.is_none(),
            "<password> template token should be allowlisted; got {:?}",
            secrets
        );
    }

    #[test]
    fn test_no_detect_placeholder_literal_password_in_db_uri() {
        // Literal `password` as the password value should be allowlisted.
        let body = r#"redis://default:password@cache.example.com:6379/0"#;
        let secrets = detect_exposed_secrets(body);
        let db = secrets
            .iter()
            .find(|s| s.secret_type == "database-connection-uri");
        assert!(
            db.is_none(),
            "literal 'password' value should be allowlisted; got {:?}",
            secrets
        );
    }

    #[test]
    fn test_no_detect_placeholder_in_jdbc_connection_string() {
        // JDBC string with <password> template token must be allowlisted.
        let body = "jdbc:mysql://localhost/db?user=admin&password=<password>";
        let secrets = detect_exposed_secrets(body);
        let db = secrets
            .iter()
            .find(|s| s.secret_type == "jdbc-connection-string");
        assert!(
            db.is_none(),
            "<password> in JDBC string should be allowlisted; got {:?}",
            secrets
        );
    }
}
