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
| **Characterization** | Proves current behavior / no panic | Soft-skip on network; field-discard after `Ok`; OR-any error strings |

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
  - UPSERT clears stale **core** satellite rows; enrichment children are replaced in a second writer transaction ([ADR 0007](adr/0007-satellite-insert-failure-policy.md)); a core satellite SQL `Err` lands in `url_partial_failures`
  - Cooperative cancel persists a `url_failures` row; CORE/ENRICHMENT satellite lists match insert call sites
  - Offline `implies` / exclude detection (fixture rulesets, no network)
  - Offline `run_scan` with local fingerprints + wiremock (status, counters, satellites, versions/`is_implied`)
  - Mid-chain RFC1918 redirect under `run_scan` is not followed (last safe hop is successful, not skipped/failed)
  - WHOIS disabled leaves `url_whois` empty; cache-seeded WHOIS writes `registrar` under `run_scan`
  - Local TLS handshake certificate fields persist through `insert_url_record` (subject, fingerprint, SANs, OIDs)
  - Config merge (`fail_on`, `--no-whois`, bool synonyms); file overlay TOML sentinels land on `Config`
  - `url_status` column defs match INSERT/UPDATE order and migrated `PRAGMA table_info`
  - Partial failure + drain exclusivity + `evaluate_exit_code`
  - Live `/status` and `/metrics` expose `partial_failures` / `satellite_insert_errors` (does not change `--fail-on`)
  - Fast concurrency smoke (`max_concurrency` ceiling)
  - `query_scan_summary` against a seeded DB
  - Export named-field intent (`redirect_count`, `body_truncated`)
  - Export `include_implied_tech` on/off and `--domain` exact match (not substring)
  - SSRF list URLs counted as **skipped** (not failed) for exit policy
  - GeoIP path soft-fail through `run_scan`
  - Wappalyzer-parity leaf tests (headers/cookies/body detection) use offline `FingerprintRuleset`/`Technology` fixtures; `#[ignore]` + full corpus is not an acceptable long-term stand-in

## What default CI does **not** prove

- Live GitHub fingerprint downloads (use `--fingerprints` fixtures or `#[ignore]` network tests)
- Full multi-OS network e2e (`just test-e2e`)

## Coverage (Codecov / tarpaulin)

Coverage upload is **informational**. Codecov does not fail CI. Do not chase line coverage with “does not panic” or soft-skip tests — prefer a failing assert when the interesting path did not run (`#[ignore]` with an honest reason, or an offline fixture).

`vendor/` is ignored: it is a rustls-only patch of upstream `whois-service`, not first-party code. Components (`storage`, `fetch`, `fingerprint`, `export`, `config`, `security`, `whois`, `geoip`, `cli`, `parse`) are informational so a strong subsystem cannot hide a weak one.

## Mutation testing

A covered line is not a checked line. `cargo-mutants` injects single-line production bugs and reports which ones the suite still passes — those **missed** mutants are the headline metric, not coverage deltas.

```bash
cargo install --locked cargo-mutants

# Module-scoped only. A repo-wide run takes hours.
cargo mutants -f src/storage/migrations.rs --test-tool=cargo
# or: just mutants src/storage/migrations.rs
```

Results land under `mutants.out/` (`caught` / `missed` / `unviable` / `timeout`). Run one module at a time locally (`just mutants FILE`). Pull requests run `cargo mutants --in-diff` against the base branch (see `.github/workflows/ci.yml`); that job fails on missed mutants. It is not a repo-wide gate.

## Placebo checklist (avoid / convert)

1. `let _ = result;` after a call under test
2. Soft-return on ruleset init failure in CI-default tests
3. Tautology / OR-any asserts as the sole claim
4. Field-discard after `Ok`
5. Zero-assert stress / “vulnerability confirmed” `println!`
6. Full CLI `--help` snapshots as the only correctness check

Prefer offline fixtures, exact expected sets, and asserting `Err` when init must fail.

## Component cost

`just test` and `just ci` stay correctness gates. Wall-clock budgets flap across machines, so they are not part of those recipes.

`just bench` does two things:

1. `cargo bench --features bench-utils` (divan, optimized) prints a table for the production matchers on a fixed page: fingerprint body and `scripts` passes at 15, 500, and 6000 technologies, secret scan of the page and of a 500 KiB script blob, HTML parse, and one SQLite upsert. The 6000-tech fixture is the stand-in for the full catalog. The vendored ruleset is about 15 technologies and will not show that cost. Compare microseconds per call across the three sizes; the 6000 row divided by 6 is microseconds per 1,000 technologies.
2. An ignored ceiling test, `component_cost_ceiling`, fails if the warm 6000-tech body pass or the script secret scan exceeds a wide debug-build limit. CI's ignored-test job runs it too. The limit is several times a local debug run so a noisy 10% swing stays green and a stage that becomes wildly more expensive does not.

```bash
just build-symbols   # flamegraph binary; see ADVANCED.md
just bench           # divan table + ceiling
```

CPU time on that fixed input is the portable stand-in for energy. The suite does not measure watt-hours.

## Sample scan validation

Local scratch DBs/exports belong under a gitignored dir (e.g. `validation_e2e/`) or names already listed in `.gitignore`.

```bash
./target/release/domain-status scan domains.txt --db-path validation_scan.db
sqlite3 validation_scan.db "SELECT COUNT(*) FROM url_status;"
./target/release/domain-status export --db-path validation_scan.db --format csv --output /tmp/validation_export.csv
```

Schema reference: [DATABASE.md](../DATABASE.md) and `migrations/` (`0001`–`0016`).

Cookbook SQL in `QUERIES.md` / `DATABASE.md` / `README.md` is regression-checked by `tests/docs_sql_smoke.rs` (syntax + schema against an empty migrated DB).
