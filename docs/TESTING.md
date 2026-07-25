# Testing posture

This project favors **behavioral tests that can fail when production breaks**, not coverage percentage as a quality gate.

## What default CI proves (`just test` / `cargo test`)

- Leaf correctness: parsers, fingerprint matching helpers, storage inserts, secrets corpus
- Orchestration contracts that must not soft-skip:
  - UPSERT clears stale satellite rows
  - Offline `implies` / exclude detection (fixture rulesets, no network)
  - Offline `run_scan` with local fingerprints + wiremock (status, counters, satellites)
  - Config merge fail_on / bool contracts
  - Partial failure accounting + `evaluate_exit_code`
  - Fast concurrency smoke (`max_concurrency` ceiling)

## What default CI does **not** prove

- Live GitHub fingerprint downloads (use `--fingerprints` fixtures or `#[ignore]` network tests)
- Slow stress / race scenarios under `tests/stress_*.rs` (run via `cargo test -- --ignored`, skipped in e2e with `--skip stress_`)
- Full multi-OS network e2e (`just test-e2e`)

## Coverage (Codecov / tarpaulin)

Coverage upload is **informational**. Codecov does not fail CI. Do not chase line coverage with “does not panic” or soft-skip tests — prefer a failing assert when the interesting path did not run (`#[ignore]` with an honest reason, or an offline fixture).

## Adding tests

Prefer:

1. Offline fixtures (local fingerprint JSON, wiremock)
2. Exact expected sets (tech names, row counts) over “non-empty” / OR-any asserts
3. Asserting `Err` when init must fail

Avoid:

1. `let _ = result;` after a call under test
2. `if init_ruleset(...).is_err() { return; }` in CI-default tests
3. Full CLI `--help` snapshots
