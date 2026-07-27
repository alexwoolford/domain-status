# ADR 0005: No-JavaScript Fingerprinting

- Status: Accepted
- Date: 2026-03-01

## Context

Technology detection is one of the scanner's major features, but full browser execution would change the operational model substantially:

- much higher runtime and resource cost
- headless browser lifecycle management
- more complicated sandboxing and attack surface
- lower determinism in tests

The current detection model is intentionally static and text-based.

## Decision

`domain_status` will not execute JavaScript as part of fingerprinting.

Technology detection is based on static evidence such as:

- headers
- cookies
- HTML
- script URLs (`scriptSrc`) and inline `<script>` text (`scripts`)
- DNS records and TLS certificate issuer (matched after DNS/TLS enrichment)
- first-party external script **bodies** when `--scan-external-scripts` is enabled (same fetch as secret scanning; static `scripts` pattern matching only)
- other response-derived patterns

`--scan-external-scripts` is opt-in because it multiplies GETs. When enabled, fetched first-party bodies improve both secret coverage and technology detection. Third-party CDN scripts remain denylisted. Bodies are matched as text only — never executed.

This keeps the scanner aligned with a lightweight, batch-oriented architecture rather than turning it into a browser automation system.

## Consequences

Positive:

- deterministic, resource-bounded scans
- simpler CI and testing story
- smaller attack surface
- easier alignment with static upstream fingerprint sources
- no wasted signal when script bodies are already fetched for secrets

Trade-offs:

- client-side-rendered technologies may be missed when the flag is off
- JavaScript-only redirects or late-loaded frameworks may not appear
- some modern SPA-heavy targets will have intentionally incomplete detection coverage without `--scan-external-scripts`
- upstream `dom` / `xhr` / runtime `js` object rules remain unmatched (by design)
- third-party CDN script content is not used for fingerprints (denylist)

## Related Code

- `src/fingerprint/detection/`
- `src/fetch/external_scripts.rs`
- `src/fetch/response/html.rs`
- `README.md`
- `docs/PRODUCTION_HARDENING.md`
