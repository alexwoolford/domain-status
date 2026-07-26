# Testing posture

This project favors **behavioral tests that can fail when production breaks**, not coverage percentage as a quality gate.

Most of the suite is still **characterization** (mirrors “code as written”). A smaller **contract** core asserts operator/CI intent. Prefer growing the latter; prune placebos that stay green when intent breaks.

## Contract vs characterization

| Kind | Meaning | Example |
|------|---------|---------|
| **Contract** | Fixture in → exact outcomes that hurt if wrong | UPSERT clears satellites; offline implies; `evaluate_exit_code` |
| **Characterization** | Proves current behavior / no panic | Soft-skip on network; `let _ = result`; OR-any error strings |

## What default CI proves (`just test` / `cargo test`)

- Leaf correctness: parsers, fingerprint matching helpers, storage inserts, secrets corpus
- Orchestration / integrity contracts that must not soft-skip:
  - UPSERT clears stale satellite rows (including full `SATELLITE_TABLES` sweep)
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
- Slow stress / narrative demos under `tests/stress_*.rs` (zero-assert `println!` suites — **not** tests)
- Full multi-OS network e2e (`just test-e2e`, which also skips `stress_`)

## Stress vs e2e

| Command | Behavior |
|---------|----------|
| GitHub CI e2e job | `cargo test -- --ignored --skip stress_` |
| `just test-e2e` | Same: ignored tests **excluding** `stress_*` |
| Manual stress demos | `cargo test --test 'stress_*' -- --ignored --nocapture` |

## Coverage (Codecov / tarpaulin)

Coverage upload is **informational**. Codecov does not fail CI. Do not chase line coverage with “does not panic” or soft-skip tests — prefer a failing assert when the interesting path did not run (`#[ignore]` with an honest reason, or an offline fixture).

## Placebo checklist (avoid / convert)

Still found historically; do not add more:

1. `let _ = result;` after a call under test
2. `if init_ruleset(...).is_err() { return; }` / `init_full_ruleset_for_tests` soft-return in CI-default tests
3. Tautology / OR-any asserts (`is_empty() \|\| !…`, `contains(A) \|\| contains(B)` as sole claim)
4. Field-discard after `Ok` (`let _ = data.field`)
5. Zero-assert stress / “vulnerability confirmed” `println!`
6. Full CLI `--help` snapshots; goldens used as the *only* correctness check for enrichment semantics

Prefer:

1. Offline fixtures (local fingerprint JSON, wiremock)
2. Exact expected sets (tech names, row counts, named CSV columns)
3. Asserting `Err` when init must fail; `#[ignore]` with reason when network is required
