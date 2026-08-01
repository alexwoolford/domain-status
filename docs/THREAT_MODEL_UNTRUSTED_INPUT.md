# Threat Model: Untrusted Input

This document records risks from malformed, oversized, or maliciously crafted external input (WHOIS/RDAP, TLS certificates, GeoIP data, HTML/response bodies) and from **outbound request routing** (SSRF / DNS rebinding), plus the mitigations in place or recommended.

**Last reviewed:** 2026-07-31 (SSRF, secret-scan, and fingerprint async posture documentation).

---

## Summary

| Area | Risk type | Mitigation status |
|------|-----------|-------------------|
| WHOIS/RDAP | DoS, panic | Size cap; parse returns Option/Result; no unwrap on untrusted in production |
| TLS/certificate | Panic, malformed DER | x509_parser returns Result; date parsing returns Err |
| GeoIP (tar.gz / .mmdb) | DoS, OOM | Entry count + entry size limits; take(read_limit); one expect on constant |
| HTML/response body | DoS, OOM | Stream + MAX_RESPONSE_BODY_SIZE; script/header/error caps |
| Secret detection | Bounded CPU (linear-time regex); panic | Rust `regex` + size caps + `spawn_blocking` (see §5) |
| Technology fingerprinting | Bounded CPU (large ruleset × body) | Rust `regex` + `spawn_blocking` (see §6) |
| Outbound HTTP (SSRF) | Internal network / metadata fetch | `Policy::none` + hop validation + `SafeResolver` (see §7) |

---

## 1. WHOIS / RDAP

**Sources:** `src/whois/` (whois-service responses, cache files).

**Risks:**

- Oversized raw text causing memory exhaustion.
- Malformed dates or fields causing panics if code used unwrap/expect on parser output.

**Current mitigations:**

- `MAX_WHOIS_RAW_TEXT_SIZE` (256 KB) and `bound_raw_text()` truncate raw WHOIS before storage/cache.
- `parse_date_string()` returns `Option`; `convert_payload` and `convert_parsed_data` use `and_then`/`or_else`; no unwrap on untrusted response data in production.
- WHOIS cache load respects `MAX_WHOIS_CACHE_FILE_SIZE` (512 KB).

**Recommendations:**

- Keep all parsing of WHOIS/RDAP response content behind `Option`/`Result`; avoid adding `.unwrap()` or `.expect()` on parser results.
- If adding new date/field parsers, use fallible APIs and document size or format assumptions.

---

## 2. TLS / certificate parsing

**Sources:** `src/tls/mod.rs`, `src/tls/extract.rs` (DER from TLS handshake, x509-parser).

**Risks:**

- Malformed DER or certificate fields could theoretically cause panics in dependency code.
- Our code could panic if it used unwrap on parse results.

**Current mitigations:**

- `parse_certificate_info_from_der()` uses `x509_parser::parse_x509_certificate(cert_der)?` and propagates errors.
- Validity date parsing uses `NaiveDateTime::parse_from_str(...).map_err(...)` and returns `Result`.
- No unwrap/expect on untrusted cert or DER in the production path.

**Recommendations:**

- Do not add `.unwrap()` or `.expect()` on x509_parser outputs or on validity/date strings derived from certificates.
- If new cert extensions or OIDs are parsed, keep parsing fallible and bound any allocation (e.g. OID list size) if feasible.

---

## 3. GeoIP (tar.gz archives and .mmdb)

**Sources:** `src/geoip/extract.rs`, `src/geoip/init/loader.rs` (downloaded tar.gz, extracted .mmdb).

**Risks:**

- Archive bombs (huge or many entries) leading to OOM or CPU DoS.
- Malformed tar/gzip causing panics in dependency code or our code.

**Current mitigations:**

- `MAX_GEOIP_ARCHIVE_ENTRY_COUNT` (128): loop bails after inspecting that many entries.
- `MAX_GEOIP_ARCHIVE_ENTRY_SIZE` (100 MB): per-entry size check before and after read; `entry.take(read_limit)` caps read.
- `read_limit` is derived from `MAX_GEOIP_ARCHIVE_ENTRY_SIZE + 1` with `.expect("GeoIP archive size limit fits in u64")` — this is a constant sanity check, not untrusted input; ensure the constant stays within u64.

**Recommendations:**

- Keep the single `.expect()` on the constant; document in code that `MAX_GEOIP_ARCHIVE_ENTRY_SIZE` must be chosen so that `+ 1` fits in u64.
- Continue to avoid unwrap/expect on entry content, path components, or decompressed streams from untrusted archives.

---

## 4. HTML / HTTP response body and headers

**Sources:** `src/fetch/response/extract.rs`, `src/fetch/response/html.rs`, favicon and header handling.

**Risks:**

- Large bodies or many headers causing OOM or CPU exhaustion.
- Malformed HTML or headers causing panics in parsers or our code.

**Current mitigations:**

- `stream_body_with_limit()` aborts when body exceeds `MAX_RESPONSE_BODY_SIZE` (2 MB) during streaming (no full body load before check).
- `MAX_HEADER_COUNT` (100), `MAX_HEADER_VALUE_LENGTH` (1000), `MAX_ERROR_MESSAGE_LENGTH` (2000).
- `MAX_HTML_TEXT_EXTRACTION_CHARS` (50 KB) for extracted content.
- `MAX_FAVICON_SIZE` (50 KB) and favicon fetch timeout for favicon bytes.

**Recommendations:**

- Keep body and header limits; do not disable or bypass streaming body limit for “convenience.”
- Any new parser (HTML, headers, etc.) should use fallible APIs and avoid unwrap on response or body data.

---

## 5. Secret detection (HTML body, headers, external scripts)

**Sources:** `src/parse/secrets.rs`, `src/parse/gitleaks.rs` (gitleaks-derived rules); invoked from HTML parse, response-header merge, and optional external-script fetch.

**Risks:**

- **CPU cost** on large bodies when many rules run (amplification), not classic catastrophic backtracking.
- Panics from slice indexing or unwrap on match data.

**Not a classic ReDoS hazard:** rules are compiled and matched with Rust’s [`regex`](https://docs.rs/regex) crate (DFA/NFA), which **guarantees linear-time** matching. Patterns are not evaluated with a backtracking engine (`fancy-regex`, Oniguruma, PCRE2, etc.), so “catastrophic backtracking that hangs a thread indefinitely” does not apply.

**Current mitigations:**

- Input bodies bounded before scan: `MAX_RESPONSE_BODY_SIZE` (2 MiB HTML), `MAX_SCRIPT_BODY_BYTES` (1 MiB per external script), header count/value caps.
- Keyword Aho-Corasick prefilter skips rules whose keywords are absent.
- Capture groups via `caps.get(n)` (no direct slice indexing on match bounds); no production unwrap/expect on match data in the hot path.
- **Off the async executor:** HTML secret scan runs inside `tokio::task::spawn_blocking` with HTML parsing; external-script and response-header secret scans likewise use `spawn_blocking`, so regex work occupies the blocking pool rather than Tokio async worker threads.
- Scan concurrency is a `JoinSet` + semaphore: a slow URL holds one permit; it does not halt the whole process.

**Residual risk:** many linear matches × multi-MiB input can still be **slow** (bounded CPU), especially with `--scan-external-scripts`. That is cost/latency, not indefinite ReDoS.

**Recommendations:**

- Keep secret regex work on `spawn_blocking` (or equivalent) when adding new call sites.
- Keep body/header size caps; do not disable them for convenience.
- Keep using `.get()` or safe indexing for substring extraction from matches.

---

## 6. Technology fingerprinting (Wappalyzer-compatible ruleset)

**Sources:** `src/fingerprint/` (merged community rulesets; thousands of technologies / pattern strings); invoked from `detect_technologies_safely` and late-signal supplements after DNS/TLS / optional external scripts.

**Risks:**

- **CPU cost** matching a large ruleset over size-capped HTML (and related haystacks). This can dominate per-URL wall time under high concurrency.
- Mistakenly running that work on Tokio **async workers** would starve I/O and timers (the anti-pattern external reviews often assume).

**Current mitigations:**

- Pattern matching uses Rust’s [`regex`](https://docs.rs/regex) crate (linear-time DFA/NFA), with compiled patterns cached (`src/fingerprint/patterns.rs`).
- HTML body capped at `MAX_RESPONSE_BODY_SIZE` (2 MiB) before fingerprinting.
- **Off the async executor:** the main pass (`detect_technologies_blocking`), body lowercasing, DNS/cert supplement, and fetched-script-text supplement all run on Tokio’s **blocking pool** via `spawn_blocking` (`src/fetch/record/detection.rs`, `src/fetch/handler/response.rs`).
- Per-URL concurrency is a `JoinSet` + semaphore: a slow fingerprint holds one permit and may queue on the blocking pool; it does not monopolize async workers used for HTTP and timeouts.

**Residual risk:** bounded CPU / blocking-pool contention under load — expected for this workload, not async-executor starvation.

**Recommendations:**

- Keep fingerprint regex and large string transforms on `spawn_blocking` when adding call sites.
- Prefer documenting this posture here (and in SECURITY.md) so reviews do not assume “thousands of regexes on async workers.”

---

## 7. SSRF / outbound request routing

**Sources:** scan HTTP clients (`src/initialization/client.rs`), redirect walker (`src/fetch/redirects.rs`), favicon / external-script fetches, GeoIP and fingerprint ruleset downloads, Chrome User-Agent version fetch.

**Risks:**

- A malicious scan target (or redirect) could point at loopback, RFC1918, link-local cloud metadata (`169.254.169.254`), or other private/reserved space.
- **DNS rebinding:** a hostname that answers with a public IP on an initial check and a private IP on the subsequent connect (TOCTOU), bypassing URL-string-only validation.
- Blindly following reqwest’s default redirect policy without re-checking each hop.

**Current mitigations (scan path):**

1. **Redirects disabled on scan clients** — `reqwest::redirect::Policy::none()` on the primary and redirect clients. Chains are walked manually by `resolve_redirect_chain` so each hop can be inspected (HTTPS→HTTP downgrade block, hop caps, logging).
2. **Per-URL and per-hop ACL** — `validate_url_safe` rejects non-http(s) schemes, localhost names, and IP literals in private/reserved space, including:
   - IPv4: loopback `127/8`, RFC1918, CGNAT `100.64/10`, link-local `169.254/16` (covers cloud metadata), multicast, documentation nets, etc.
   - IPv6: `::`, `::1`, ULA `fc00::/7`, link-local `fe80::/10`, multicast `ff00::/8`, documentation `2001:db8::/32`, IPv4-mapped delegated to the IPv4 checks
3. **DNS filter before connect** — `SafeResolver` (`src/security/safe_resolver.rs`) implements `reqwest::dns::Resolve`: after hickory lookup, only public IPs are returned; if all answers are private/reserved, resolution fails with `SSRF blocked: all resolved IPs … are private/reserved` **before** TCP connect. This is the primary DNS-rebinding mitigation (each request re-resolves through the same filter).
4. **Auxiliary downloads** (GeoIP, fingerprint ruleset, UA version) use `ssrf_safe_redirect_policy()` and (where applicable) `SafeResolver` so legitimate CDN redirects still work while private targets are stopped.

**Intentional exception:**

- `allow_localhost_for_tests` permits loopback for in-process mock servers. It is **not** exposed via the public CLI; config merge keeps production scans SSRF-strict.

**Recommendations:**

- Do not switch scan clients back to default auto-follow redirects.
- Keep pairing any new outbound HTTP client with `validate_url_safe` (and `SafeResolver` when hostnames are resolved).
- Prefer documenting SSRF posture here (and in SECURITY.md) so external reviews do not assume default-reqwest behavior.

---

## 8. General practices

- **No unwrap/expect on untrusted data:** Reserve unwrap/expect for programming invariants (e.g. “this constant fits in u64”) or test code, not for parser or network output.
- **Size caps first:** Where feasible, enforce entry/body/header limits before full parse or allocation.
- **Structured errors:** Use `Result`/`Option` and `?` so that malformed input produces errors instead of panics.
- **Outbound SSRF:** Treat every new fetch path as untrusted routing; see §7.

This threat model should be updated when new untrusted input sources are added, when outbound client configuration changes, or when limits or parsing logic change.
