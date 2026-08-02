# ADR 0003: TLS Capture Versus Validation

- Status: Accepted
- Date: 2026-03-01
- Updated: 2026-08-02

## Context

`domain_status` is an observational scanner. We want certificate and TLS metadata even when a site is misconfigured, expired, hostname-mismatched, or otherwise invalid from a browser trust perspective — without turning the main HTTP client into an insecure browser substitute.

Page-fetch clients live in `src/initialization/client.rs`. Dedicated TLS observation lives in `src/tls/`.

## Decision

Split **page fetch** from **TLS capture**:

- **Page-fetch HTTP clients** use **strict** rustls verification (invalid certificates and hostnames fail the request). A failed fetch is still a useful observation (recorded as failure / skip), not a reason to disable trust.
- **TLS capture** uses a separate AcceptAll path so certificate fields, SANs, fingerprints, and related facts can still be collected when the leaf would fail browser trust.
- Redirect handling remains manual and SSRF-aware (`Policy::none` + hop validation + `SafeResolver`).
- Trust outcomes are stored as fact columns (`cert_is_self_signed`, `cert_is_wildcard`, `cert_is_mismatched`, `tls_version`, validity timestamps) for SQL / export — not as a separate “security warnings” analysis layer.

## Consequences

Positive:

- Page fetch does not silently accept broken TLS as a successful HTTPS session.
- Misconfigured HTTPS services remain observable via the capture path and failure records.
- Consumers query fact columns rather than a precomputed warning table.

Trade-offs:

- Capture success does not imply the page-fetch client trusted the certificate.
- Dual paths must stay documented so “we got a cert” is not read as “HTTPS was valid.”

## Guardrails

- Redirects are not automatically followed by reqwest.
- DNS resolution remains SSRF-aware through the safe resolver path.
- `src/security/` holds SSRF / HSTS / URL validation helpers — not a post-hoc warning analyzer.

## Related Code

- `src/initialization/client.rs` (strict page-fetch TLS)
- `src/tls/` (capture path)
- `src/security/` (SSRF, HSTS, URL validation)
- `SECURITY.md`
