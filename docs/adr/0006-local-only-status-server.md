# ADR 0006: Local-Only Status Server

- Status: Accepted
- Date: 2026-03-01

## Context

Long-running scans benefit from live progress and Prometheus-friendly metrics, but the tool is not intended to operate as a multi-tenant network service. Adding authentication, authorization, and remote-service hardening would complicate a feature whose main job is local observability during a batch run.

The current implementation lives in `src/status_server/`.

## Decision

The status server will:

- be opt-in via `--status-port`
- bind to `127.0.0.1:<port>`
- expose `/status` and `/metrics`
- provide no built-in authentication
- be treated as a local monitoring helper, not a public API service

This is an intentional design constraint, not an accidental omission.

## Consequences

Positive:

- simple operational model
- no auth/session/key-management burden in the scanner
- straightforward local Prometheus scraping and shell-based inspection

Trade-offs:

- remote access requires explicit tunneling or an external protected proxy
- users must not assume it is safe to expose directly to untrusted networks

## Related Code

- `src/status_server/mod.rs`
- `src/status_server/handlers/status.rs`
- `src/status_server/handlers/metrics.rs`
- `README.md`
- `docs/PRODUCTION_HARDENING.md`
