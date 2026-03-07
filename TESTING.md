# Testing

## Quick Start

```bash
# Deterministic CI-oriented suite
cargo test --lib --tests

# Run a specific test or module
cargo test status_server::handlers::status

# Show stdout/stderr for a test
cargo test status_server::handlers::metrics -- --nocapture
```

## Quality Gates

```bash
# Format code
cargo fmt --check

# Run linter
cargo clippy --all-targets --all-features --locked -- -D warnings

# Security audit
cargo audit

# Validate public docs and examples
cargo test --doc
```

## Test Taxonomy

### Unit tests

- Location: `src/**/tests` modules.
- Requirements: no live network, no wall-clock sleeps, no process-global mutable state.
- Preferred tools: fixtures, fake inputs, generated local data, injected elapsed time or clocks.
- Good examples: `models` enum mapping, `tls` DER parsing, `whois` payload mapping, `storage` retry behavior, `status_server` response builders.

### Deterministic integration tests

- Location: `tests/*.rs` or module-level tests that exercise multiple components together.
- Requirements: local-only dependencies such as SQLite, temp dirs, in-memory routers, or generated certificates.
- Preferred patterns:
  - Use `Router::oneshot` for `status_server` instead of binding a real port unless bind behavior itself is under test.
  - Use temp SQLite databases and real migrations for storage/finalization coverage.
  - Use generated certificates or local fixtures for TLS parsing.
  - Use fake lookup closures/backends for WHOIS and local cache directories for cache behavior.

### Manual / live-network tests

- These are intentionally `#[ignore]` and are not part of the deterministic CI signal.
- Includes bug-repro or environmental checks such as `tests/http_timeout_bug.rs`, `tests/whois_timeout_bug.rs`, and live/stress scans.
- Run them explicitly with `cargo test -- --ignored`.
- If one of these finds a real bug, add or update a deterministic regression test before fixing the implementation.

### Stress and resilience tests

- Files matching `tests/stress_*.rs` and other load-oriented suites are exploratory, not correctness gates.
- Keep them ignored by default.
- Use them to study throughput, memory growth, locking behavior, and failure isolation.
- Do not treat a passing stress test as a substitute for a deterministic regression test.

## What To Avoid

- Tests that mirror production logic instead of calling it.
- Tests that only assert string construction or constants unless the string/constant is itself a user-facing contract.
- Tests that accept `is_ok() || is_err()` without asserting the intended behavior.
- Tests that primarily prove Tokio, Clap, `Arc`, or another dependency works.
- Tests that rely on public internet access or timing races in the default CI suite.

## Current Strategy

- CLI parsing and exit-code behavior are tested through the real library CLI types in `src/cli.rs`; do not recreate mirror clap structs in integration tests.
- `status_server` behavior is tested through pure response/metrics builders plus router integration.
- WHOIS behavior is split into deterministic payload mapping, cache-store behavior, and injected lookup tests.
- TLS parsing should prefer DER fixtures or generated certificates over live HTTPS handshakes.
- GeoIP lookup tests should focus on deterministic local inputs unless a local MMDB fixture is available.

## Sample Scan Validation

To sanity-check columns and `url_exposed_secrets` after changes:

```bash
./target/release/domain_status scan url-list.txt --db-path validation_scan.db
sqlite3 validation_scan.db "SELECT COUNT(*) FROM url_status; SELECT secret_type, COUNT(*) FROM url_exposed_secrets GROUP BY secret_type;"
./target/release/domain_status export --db-path validation_scan.db --format csv --output /tmp/validation_export.csv
```

Expect: `url_status` row count matches successful URLs from the run; `url_exposed_secrets` uses gitleaks rule ids (for example `sourcegraph-access-token` and `gcp-api-key`); no empty `ip_address` values because DNS failures use the placeholder `unknown`.
Expect: `url_status` row count matches successful URLs from the run; `url_exposed_secrets` uses gitleaks-style rule ids (for example `sourcegraph-access-token` and `gcp-api-key`); exported and stored `ip_address` values may be empty when DNS resolution failed because the DB layer now persists absence as an empty string fallback rather than the old `unknown` sentinel.

See `.github/workflows/ci.yml` for the full CI pipeline.
