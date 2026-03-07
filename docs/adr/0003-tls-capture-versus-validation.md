# ADR 0003: TLS Capture Versus Validation

- Status: Accepted
- Date: 2026-03-01

## Context

`domain_status` is an observational scanner, not a trust-establishing HTTPS client for end-user traffic. We want to capture certificate and TLS metadata even when a site is misconfigured, expired, hostname-mismatched, or otherwise invalid from a browser trust perspective.

The current HTTP clients are configured in `src/initialization/client.rs`, while security interpretation of the captured data happens elsewhere.

## Decision

The scanner will prefer **capture** over **transport validation** during collection:

- request clients allow invalid certificates
- request clients allow invalid hostnames
- redirect handling is still manual and SSRF-aware
- certificate properties and trust-related concerns are analyzed after capture rather than enforced by the transport layer

In short: the tool is allowed to observe broken TLS so it can report on broken TLS.

## Consequences

Positive:

- misconfigured or expired HTTPS services remain observable
- the scanner can inventory certificate details for sites that would fail strict validation
- TLS security analysis is based on captured evidence rather than early transport rejection

Trade-offs:

- these clients are not appropriate as general-purpose "secure browser" clients
- developers must not assume a successful request implies certificate trustworthiness
- documentation must be explicit so consumers do not misread collection success as validation success

## Guardrails

- redirects are not automatically followed
- DNS resolution remains SSRF-aware through the safe resolver path
- downstream security analysis is responsible for classifying weak or invalid TLS properties

## Related Code

- `src/initialization/client.rs`
- `src/tls/mod.rs`
- `src/security/analysis.rs`
- `README.md`
