# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

`domain_status` is a concurrent URL/domain scanner CLI tool written in Rust. It captures HTTP status, TLS certificates, DNS records, WHOIS data, GeoIP, technology fingerprints, and exposed secrets in a single pass, storing results in SQLite. Static analysis only (no JS execution).

## Build & Development Commands

Uses `just` as the task runner (install: `cargo install just`).

| Task | Command |
|------|---------|
| Build release | `just build` or `cargo build --release --locked` |
| Run all checks | `just check` (fmt + lint + test) |
| Format | `just fmt` |
| Lint | `just lint` (clippy with `--locked -D warnings`) |
| Run tests | `just test` (excludes network-dependent) |
| Run single test | `cargo test test_name --all-features --locked` |
| Run E2E tests | `just test-e2e` (requires network, runs `#[ignore]` tests) |
| Docs check | `just docs-check` (rustdoc examples + warning cleanliness) |
| Full CI locally | `just ci` |
| Coverage | `just coverage` (generates HTML via tarpaulin) |
| Security audit | `just audit` / `just deny` |
| Update snapshots | `cargo insta review` |

## Architecture

### Six-Phase Scan Pipeline (`src/run/`)

1. **Init** (`init.rs`) — DB pool, HTTP/DNS clients, fingerprint ruleset, GeoIP DB, WHOIS cache, User-Agent update
2. **Status Server** (optional) — Axum HTTP server with `/health`, `/status`, `/metrics`
3. **URL Processing Loop** (`mod.rs`) — Concurrent dispatch via Tokio JoinSet, token-bucket rate limiting
4. **Per-URL Task** (`task.rs`) — HTTP fetch, redirect chain, DNS, TLS, HTML parsing, fingerprinting, enrichments
5. **Storage** — SQLite inserts with UPSERT semantics, per-URL transactions
6. **Finalization** (`finalize.rs`) — Drain queue, compute stats, export (CSV/JSONL/Parquet)

### Key Source Modules

- **`src/cli.rs`** — CLI parsing and command dispatch (clap derive)
- **`src/run/`** — Scan orchestration (entry: `run_scan()`)
- **`src/fetch/`** — HTTP requests, redirect resolution, DNS, favicon hashing
- **`src/fingerprint/`** — Technology detection via pattern matching (`patterns.rs` has all rules)
- **`src/storage/`** — SQLite layer (pool, migrations, insert/, failure/)
- **`src/export/`** — CSV, JSONL, Parquet export with query builders
- **`src/whois/`** — WHOIS/RDAP lookup with disk-based caching
- **`src/tls/`** — Certificate DER parsing, cipher suite extraction
- **`src/geoip/`** — MaxMind MMDB extraction and IP-to-location lookup
- **`src/config/`** — Config struct with file + env + CLI merging
- **`src/parse/`** — JWT claims parsing, exposed secret detection
- **`src/status_server/`** — Live monitoring HTTP endpoints
- **`src/adaptive_rate_limiter/`** — Token bucket rate limiting

### Database

SQLite with WAL mode. Schema in `migrations/` (8 migration files). Main tables: `runs`, `url_status` (fact table), `url_failures`, plus ~25 satellite tables for DNS records, TLS certs, headers, technologies, WHOIS, GeoIP, secrets, etc. Full schema documented in `DATABASE.md`.

### Workspace Structure

Cargo workspace with a `cli/` member (`domain_status_cli`) for CLI argument definitions. `vendor/whois-service` is a patched dependency to eliminate a RUSTSEC advisory.

## Code Conventions

- **MSRV**: Rust 1.85+ (Edition 2021)
- **No unsafe code** — `#![deny(unsafe_code)]` in `lib.rs`
- **No `.unwrap()`** — use `Result`/`anyhow` throughout
- **Line length**: 100 chars (`rustfmt.toml`)
- **Clippy**: 40+ deny-level lints including `too_many_lines` (>100), `cognitive_complexity`, `cast_possible_truncation`, `needless_pass_by_value`
- **TLS**: rustls only (no native-tls/OpenSSL dependency)
- **Tests**: `#[ignore]` for network-dependent tests; `proptest` for property-based; `insta` for snapshots; `wiremock`/`httptest` for HTTP mocking; `rstest` for parameterized

## Testing Notes

- Snapshot tests use `insta` with YAML format — run `cargo insta review` after updating
- Integration tests in `tests/` use mock HTTP servers and temp SQLite databases
- Stress tests (`tests/stress_*.rs`) are excluded from E2E runs
- Pre-commit hooks available: `just install-hooks` (includes gitleaks secret scanning)
