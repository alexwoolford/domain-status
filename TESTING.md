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
- Prefer `just test-e2e` (or `cargo test --all-features --all-targets --locked -- --ignored --skip stress_`) for network e2e; stress demos stay separate via `--skip stress_`.
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

To sanity-check columns and `url_exposed_secrets` after changes, use the short recipe below. For a full end-to-end validation of every table, export format, and timings, use the **Full E2E validation checklist** that follows.

### Quick sanity check

```bash
# domains.txt: one URL or domain per line
./target/release/domain_status scan domains.txt --db-path validation_scan.db
sqlite3 validation_scan.db "SELECT COUNT(*) FROM url_status; SELECT secret_type, COUNT(*) FROM url_exposed_secrets GROUP BY secret_type;"
./target/release/domain_status export --db-path validation_scan.db --format csv --output /tmp/validation_export.csv
```

Expect: `url_status` row count matches successful URLs from the run; `url_exposed_secrets` uses gitleaks-style rule ids (for example `sourcegraph-access-token` and `gcp-api-key`); exported and stored `ip_address` values may be empty when DNS resolution failed because the DB layer now persists absence as an empty string fallback rather than the old `unknown` sentinel.

### Full E2E validation checklist

Use this when you need to validate **everything**: database tables/columns, all export formats, timings, and optionally the status server.

**Prerequisites**

- Build: `cargo build --release --locked`
- Input: a domain list file (for example `domains.txt`)

**1. Run scan**

```bash
./target/release/domain_status scan domains.txt --db-path validation_scan.db
```

Optional: add `--status-port 8080` to exercise the status server during the run (see step 5).

**2. Database validation** (e.g. with `sqlite3 validation_scan.db`)

- **runs:** One row; `run_id`, `start_time_ms`, `end_time_ms`, `elapsed_seconds`, `total_urls`, `successful_urls`, `failed_urls`, `skipped_urls` populated; `successful_urls + failed_urls + skipped_urls ≈ total_urls`; `elapsed_seconds` > 0 and roughly matches wall-clock.
- **url_status:** Row count = successful URLs (≤ input size); each row has `initial_domain`, `final_domain`, `http_status` in a sensible range (e.g. 200–599), `response_time_seconds` ≥ 0, `observed_at_ms` and `run_id` set; `ip_address` may be empty when DNS failed.
- **url_failures:** Rows for failed URLs; `runs.successful_urls + runs.failed_urls + runs.skipped_urls` should match `total_urls` (attempted + skipped).
- **Satellite tables:** At least some rows in `url_technologies`, `url_whois` (where WHOIS succeeded), and optionally `url_exposed_secrets`; `url_exposed_secrets.secret_type` uses gitleaks-style rule ids. Spot-check `url_geoip`, `url_nameservers`, `url_txt_records`, `url_mx_records`, `url_security_headers` where applicable.
- **Timings:** `runs.elapsed_seconds` and `url_status.response_time_seconds` present and sensible; no null/negative where NOT NULL.

Reference: [DATABASE.md](DATABASE.md) and `migrations/` (`0001`–`0012`) for schema.

**3. Export format validation**

- **CSV:**
  `./target/release/domain_status export --db-path validation_scan.db --format csv --output validation_export.csv`
  File exists; row count = header + one line per url_status row; header includes expected columns (url, initial_domain, final_domain, ip_address, http_status, technologies, whois-related columns, nameservers, exposed_secrets, etc.). Spot-check a sample row for non-empty values where expected.

- **JSONL:**
  `./target/release/domain_status export --db-path validation_scan.db --format jsonl --output validation_export.jsonl`
  File exists; one JSON object per line; line count = url_status row count. Spot-check one object for required top-level fields (e.g. url, http_status, dns, technologies, whois if present).

- **Parquet:**
  `./target/release/domain_status export --db-path validation_scan.db --format parquet --output validation_export.parquet`
  File exists; row count matches url_status. Optionally verify schema/row count with parquet-tools or a small script.

**4. Status server (optional)**

If the scan was run with `--status-port 8080`:

- `curl -s http://127.0.0.1:8080/health` returns 200 and body `ok`.
- `curl -s http://127.0.0.1:8080/status | jq` returns 200 and JSON with run progress/state.
- `curl -s http://127.0.0.1:8080/metrics` returns 200 and Prometheus-style text.

**5. Cleanup**

Validation artifacts (`validation_scan.db`, `validation_export.*`) are in `.gitignore`; remove or keep locally as needed.

See `.github/workflows/ci.yml` for the full CI pipeline.
