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
- script URLs
- other response-derived patterns

This keeps the scanner aligned with a lightweight, batch-oriented architecture rather than turning it into a browser automation system.

## Consequences

Positive:

- deterministic, resource-bounded scans
- simpler CI and testing story
- smaller attack surface
- easier alignment with static upstream fingerprint sources

Trade-offs:

- client-side-rendered technologies may be missed
- JavaScript-only redirects or late-loaded frameworks may not appear
- some modern SPA-heavy targets will have intentionally incomplete detection coverage

## Related Code

- `src/fingerprint/detection/`
- `src/fetch/response/html.rs`
- `README.md`
- `docs/PRODUCTION_HARDENING.md`
