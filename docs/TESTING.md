# Testing

This project favors **behavioral tests that can fail when production breaks**, not coverage percentage as a quality gate.

Most of the suite is still **characterization** (mirrors “code as written”). A smaller **contract** core asserts operator/CI intent. Prefer growing the latter; prune placebos that stay green when intent breaks.

## Quick start

```bash
# Deterministic CI-oriented suite
cargo test --lib --tests

# Run a specific test or module
cargo test status_server::handlers::status

# Show stdout/stderr for a test
cargo test status_server::handlers::metrics -- --nocapture
```

Also: `just test` (default suite), `just test-e2e` (ignored network tests), `just check` (fmt + lint + docs + test).

## Quality gates

```bash
cargo fmt --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo audit
cargo test --doc
```

## Contract vs characterization

| Kind | Meaning | Example |
|------|---------|---------|
| **Contract** | Fixture in → exact outcomes that hurt if wrong | UPSERT clears satellites; offline implies; `evaluate_exit_code` |
| **Characterization** | Proves current behavior / no panic | Soft-skip on network; `let _ = result`; OR-any error strings |

## Test taxonomy

### Unit tests

- Location: `src/**/tests` modules.
- Requirements: no live network, no wall-clock sleeps, no process-global mutable state.
- Preferred tools: fixtures, fake inputs, generated local data, injected elapsed time or clocks.

### Deterministic integration tests

- Location: `tests/*.rs` or module-level tests that exercise multiple components together.
- Requirements: local-only dependencies such as SQLite, temp dirs, in-memory routers, or generated certificates.
- Preferred patterns: `Router::oneshot` for status server; temp SQLite + real migrations; DER/fixture TLS; fake WHOIS closures.

### Manual / live-network tests

- Intentionally `#[ignore]`; not part of the deterministic CI signal.
- Prefer `just test-e2e` (or `cargo test --all-features --all-targets --locked -- --ignored`).
- If one finds a real bug, add a deterministic regression before fixing production code.

## What default CI proves (`just test` / `cargo test`)

- Leaf correctness: parsers, fingerprint matching helpers, storage inserts, secrets corpus
- Orchestration / integrity contracts that must not soft-skip:
  - UPSERT clears stale satellite rows (including full `URL_STATUS_SATELLITE_TABLES` sweep)
  - Offline `implies` / exclude detection (fixture rulesets, no network)
  - Offline `run_scan` with local fingerprints + wiremock (status, counters, satellites, versions/`is_implied`)
  - Config merge (`fail_on`, `--no-whois`, bool synonyms)
  - Partial failure + drain exclusivity + `evaluate_exit_code`
  - Fast concurrency smoke (`max_concurrency` ceiling)
  - `query_scan_summary` against a seeded DB
  - Export named-field intent (`redirect_count`, `body_truncated`)
  - SSRF list URLs counted as **skipped** (not failed) for exit policy
  - GeoIP path soft-fail through `run_scan`
  - Wappalyzer-parity leaf tests (headers/cookies/body detection) use offline `FingerprintRuleset`/`Technology` fixtures; `#[ignore]` + full corpus is not an acceptable long-term stand-in

## What default CI does **not** prove

- Live GitHub fingerprint downloads (use `--fingerprints` fixtures or `#[ignore]` network tests)
- Full multi-OS network e2e (`just test-e2e`)

## Coverage (Codecov / tarpaulin)

Coverage upload is **informational**. Codecov does not fail CI. Do not chase line coverage with “does not panic” or soft-skip tests — prefer a failing assert when the interesting path did not run (`#[ignore]` with an honest reason, or an offline fixture).

## Placebo checklist (avoid / convert)

1. `let _ = result;` after a call under test
2. Soft-return on ruleset init failure in CI-default tests
3. Tautology / OR-any asserts as the sole claim
4. Field-discard after `Ok`
5. Zero-assert stress / “vulnerability confirmed” `println!`
6. Full CLI `--help` snapshots as the only correctness check

Prefer offline fixtures, exact expected sets, and asserting `Err` when init must fail.

## Sample scan validation

Local scratch DBs/exports belong under a gitignored dir (e.g. `validation_e2e/`) or names already listed in `.gitignore`.

```bash
./target/release/domain_status scan domains.txt --db-path validation_scan.db
sqlite3 validation_scan.db "SELECT COUNT(*) FROM url_status;"
./target/release/domain_status export --db-path validation_scan.db --format csv --output /tmp/validation_export.csv
```

Schema reference: [DATABASE.md](../DATABASE.md) and `migrations/` (`0001`–`0015`).

Cookbook SQL in `QUERIES.md` / `DATABASE.md` / `README.md` is regression-checked by `tests/docs_sql_smoke.rs` (syntax + schema against an empty migrated DB).
