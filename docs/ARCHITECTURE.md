# Architecture Index

This document is a lightweight map from major code areas to the operational and architectural documents that explain them.

## System Flow

At a high level:

1. CLI parses a scan or export command.
2. Scan startup initializes caches, clients, resolver, rate limiting, database pool, and migrations.
3. URL processing gathers HTTP, DNS, TLS, fingerprint, and optional enrichment data.
4. Results are written into SQLite and later exported as CSV, JSONL, or Parquet.
5. Optional status endpoints expose live progress and metrics.

## Code Map

| Area | Primary code | What it owns | Related docs |
|------|--------------|--------------|--------------|
| CLI and exit semantics | `src/cli.rs`, `src/main.rs` | argument parsing, command dispatch, exit codes | `README.md`, `docs/EXIT_CODES.md` |
| Scan orchestration | `src/run/`, `src/app/` | startup, shared resources, shutdown, reporting | `README.md`, `docs/PRODUCTION_HARDENING.md` |
| HTTP and DNS initialization | `src/initialization/` | clients, resolver, rate limiting, logging | `docs/PRODUCTION_HARDENING.md` |
| Fingerprinting | `src/fingerprint/` | ruleset loading, caching, static detection | [ADR 0001](adr/0001-fingerprint-ruleset-sourcing-and-caching.md), [ADR 0005](adr/0005-no-javascript-fingerprinting.md) |
| GeoIP | `src/geoip/` | MaxMind loading, caching, lookup | `docs/PRODUCTION_HARDENING.md` |
| WHOIS/RDAP | `src/whois/` | best-effort WHOIS lookup and caching | [ADR 0002](adr/0002-enrichment-failure-policy.md) |
| TLS capture and analysis | `src/tls/`, `src/security/` | certificate capture and security interpretation | [ADR 0003](adr/0003-tls-capture-versus-validation.md) |
| Storage | `src/storage/` | SQLite pool, migrations, inserts, query helpers | `DATABASE.md`, [ADR 0004](adr/0004-sqlite-first-analytical-storage.md) |
| Export | `src/export/` | CSV, JSONL, Parquet transforms | `README.md`, `DATABASE.md` |
| Status server | `src/status_server/` | `/status` and `/metrics` | [ADR 0006](adr/0006-local-only-status-server.md), `docs/PRODUCTION_HARDENING.md` |
| Tests and CI signal | `tests/`, `.github/workflows/ci.yml` | deterministic tests, ignored network tests, CI gates | `TESTING.md`, `CONTRIBUTING.md` |

## ADR Index

| ADR | Topic |
|-----|-------|
| [ADR 0001](adr/0001-fingerprint-ruleset-sourcing-and-caching.md) | Fingerprint ruleset sourcing and caching |
| [ADR 0002](adr/0002-enrichment-failure-policy.md) | Mandatory vs best-effort enrichment behavior |
| [ADR 0003](adr/0003-tls-capture-versus-validation.md) | Observe TLS even when transport validation would fail |
| [ADR 0004](adr/0004-sqlite-first-analytical-storage.md) | SQLite as the primary runtime and export source of truth |
| [ADR 0005](adr/0005-no-javascript-fingerprinting.md) | Static fingerprinting only; no browser execution |
| [ADR 0006](adr/0006-local-only-status-server.md) | Status server binds locally and ships without auth |

## Operational Docs

- `README.md`
- `docs/EXIT_CODES.md`
- `docs/PRODUCTION_HARDENING.md`
- `DATABASE.md`
- `docs/DEVELOPER_BOOTSTRAP.md`
- `CONTRIBUTING.md`
- `TESTING.md`
