# Threat Model: Untrusted Input

This document records risks from malformed, oversized, or maliciously crafted external input (WHOIS/RDAP, TLS certificates, GeoIP data, HTML/response bodies) and the mitigations in place or recommended.

**Last reviewed:** 2026-03-01 (Security Posture Report implementation).

---

## Summary

| Area | Risk type | Mitigation status |
|------|-----------|-------------------|
| WHOIS/RDAP | DoS, panic | Size cap; parse returns Option/Result; no unwrap on untrusted in production |
| TLS/certificate | Panic, malformed DER | x509_parser returns Result; date parsing returns Err |
| GeoIP (tar.gz / .mmdb) | DoS, OOM | Entry count + entry size limits; take(read_limit); one expect on constant |
| HTML/response body | DoS, OOM | Stream + MAX_RESPONSE_BODY_SIZE; script/header/error caps |
| Secret detection | Regex DoS, panic | Body pre-limited; capture groups via .get(); no slice indexing on match |

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
- `MAX_SCRIPT_CONTENT_SIZE` (100 KB) and `MAX_HTML_TEXT_EXTRACTION_CHARS` (50 KB) for extracted content.
- `MAX_FAVICON_SIZE` (50 KB) and favicon fetch timeout for favicon bytes.

**Recommendations:**

- Keep body and header limits; do not disable or bypass streaming body limit for “convenience.”
- Any new parser (HTML, headers, etc.) should use fallible APIs and avoid unwrap on response or body data.

---

## 5. Secret detection (HTML body)

**Sources:** `src/parse/secrets.rs` (gitleaks-style rules over HTML body).

**Risks:**

- Regex DoS (ReDoS) if a rule’s regex and input interact badly.
- Panics from slice indexing or unwrap on match data.

**Current mitigations:**

- Input body is already bounded by `MAX_RESPONSE_BODY_SIZE` before secret detection.
- Capture groups accessed via `caps.get(n)` (no direct slice indexing on match bounds).
- No production unwrap/expect on match or capture data in the hot path.

**Recommendations:**

- When adding or updating rules, prefer bounded or linear regex patterns where possible; avoid nested quantifiers on overlapping regions.
- Keep using `.get()` or safe indexing for any substring extraction from matches.

---

## 6. General practices

- **No unwrap/expect on untrusted data:** Reserve unwrap/expect for programming invariants (e.g. “this constant fits in u64”) or test code, not for parser or network output.
- **Size caps first:** Where feasible, enforce entry/body/header limits before full parse or allocation.
- **Structured errors:** Use `Result`/`Option` and `?` so that malformed input produces errors instead of panics.

This threat model should be updated when new untrusted input sources are added or when limits or parsing logic change.
