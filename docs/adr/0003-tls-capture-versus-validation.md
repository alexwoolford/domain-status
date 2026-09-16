# ADR 0003: TLS Capture Versus Validation

- Status: Accepted
- Date: 2026-03-01
- Updated: 2026-09-16

## Context

`domain_status` is an observational scanner. Certificate facts should be collected without turning the main HTTP client into an insecure browser substitute. Invalid TLS on the page GET is a failed observation (`url_failures`), not a reason to disable trust on that client.

Page-fetch clients live in `src/initialization/client.rs`. Dedicated TLS observation lives in `src/tls/`.

## Decision

Split **page fetch** from **TLS capture**:

- **Page-fetch HTTP clients** use **strict** rustls verification (invalid certificates and hostnames fail the request). A failed fetch is still a useful observation (recorded as failure / skip), not a reason to disable trust.
- **TLS capture** uses a separate AcceptAll path so certificate fields, SANs, fingerprints, and related facts can be collected independently of page-fetch trust **when that path runs**. It runs only after a successful strict HTTPS GET (`fetch_tls_and_dns`). Expired, self-signed, or hostname-mismatched sites fail the page client and land in `url_failures` with no cert columns.
- Redirect handling remains manual and SSRF-aware (`Policy::none` + hop validation + `SafeResolver`).
- Trust outcomes are stored as fact columns (`cert_is_self_signed`, `cert_is_wildcard`, `cert_is_mismatched`, `tls_version`, validity timestamps) for SQL / export — not as a separate “security warnings” analysis layer.

## Consequences

Positive:

- Page fetch does not silently accept broken TLS as a successful HTTPS session.
- When the page GET succeeds, certificate facts come from a documented second handshake, not from weakening the scan client.
- Consumers query fact columns rather than a precomputed warning table.

Trade-offs:

- Invalid-cert HTTPS is a failed fetch (`url_failures`), not an AcceptAll observation. Running capture on the HTTP failure path is a later product change, not implied by this split.
- Capture success does not imply the page-fetch client trusted the certificate (the two handshakes are independent).
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
