# Code review: issues from feedback

This document investigates each of the seven reported issues and records findings and recommendations.

---

## 1. `status_server/error.rs` – dead code and `#[allow(dead_code)]`

**Location:** `src/status_server/error.rs`

**Finding:** The whole module is currently unused. The type is intended for future fallible handlers (see doccomment: “Current handlers (health, metrics, status) are infallible; use this when adding new endpoints that may fail”). The struct, its `Display`/`Error`/`IntoResponse` impls, and the constructors `internal()` and `unavailable()` are all annotated with `#[allow(dead_code)]`.

**Recommendation:**

- **Option A:** Use it in at least one place (e.g. wrap a fallible operation in a handler and return `Result<_, StatusServerError>`), then remove the `#[allow(dead_code)]` attributes.
- **Option B:** If you want to keep it as reserved for future use, keep a single module-level `#[allow(dead_code)]` and add a short comment that the type is intentionally unused until fallible handlers are added.
- Avoid per-item `#[allow(dead_code)]` on every symbol; it hides real dead code and makes the crate noisier.

---

## 2. `error_handling/reqwest_ext.rs` – unused in production, only in tests

**Location:** `src/error_handling/reqwest_ext.rs`

**Finding:** `ReqwestErrorExt` is re-exported from the crate and used only in tests (e.g. in `categorization.rs` tests). Production code uses the free function `categorize_reqwest_error()` and does not call `.categorize()` or `.is_retriable()` on `reqwest::Error`.

**Recommendation:**

- **Option A:** Use the trait in production (e.g. in fetch/retry code): call `error.categorize()` for stats and `error.is_retriable()` for retry decisions, then you can remove the “only in tests” concern.
- **Option B:** If you do not want the trait in the production API, move it (and any tests that depend on it) behind `#[cfg(test)]` or a `test-utils` module so the main API stays minimal.

**Done:** `update_error_stats` now uses `ReqwestErrorExt::categorize()` (i.e. `error.categorize()`), so the trait is used in production (fetch/handler/request). `update_error_stats` is now synchronous.

---

## 3. `config/merge.rs` (lines 132–151) – merge overwrites file/env with CLI defaults

**Location:** `src/config/merge.rs`, `merge_file_env_and_cli()`

**Finding:** The function builds config as: (1) `Config::default()`, (2) apply `file_env_map`, (3) then overwrite **every** field from `cli_config`. The `cli_config` value is produced by `config_from_scan_command(scan_cmd)`, where `scan_cmd` is the clap-parsed struct. For any option the user did not set, clap fills in its default. So file/env values are overwritten by CLI **defaults**, not only by explicitly provided CLI values. That violates the intended precedence “CLI > env > config file > defaults” for options the user did not pass.

**Example:** User sets `DOMAIN_STATUS_LOG_LEVEL=debug` in env and does not pass `--log-level`. Clap still gives `log_level: Info` (default). Merge then overwrites the file/env `debug` with `Info`.

**Recommendation:** Only overwrite with `cli_config` for fields that were **explicitly** set by the user. Options:

- Use clap’s “default missing” or “explicitly set” tracking (e.g. `ArgMatches::indices_of` or custom logic) and only copy those fields from `cli_config` into the merged config.
- Or build merged config field-by-field: for each field, if CLI explicitly set → use CLI; else if in file/env → use that; else use default.

This is a behavioral bug that should be confirmed with a test or manual run (e.g. set env, omit CLI flag, assert final config uses env value).

**Done:** Implemented using `ArgMatches::value_source()` (CommandLine or EnvVariable). CLI now uses `get_matches_from` and passes `cli_explicit: Option<&[&str]>` to `merge_file_env_and_cli`. When `Some(keys)`, only those fields overwrite file+env. Test `config::merge::tests::test_merge_preserves_file_env_when_cli_not_explicit` added.

---

## 4. `error_handling/stats.rs` – defensive logging for “impossible” states

**Location:** `src/error_handling/stats.rs`, all six methods that touch the maps

**Finding:** Each of `increment_error`, `increment_warning`, `increment_info`, `get_error_count`, `get_warning_count`, and `get_info_count` contains a branch for “key not in map” with a log saying it indicates a bug in initialization. With the current design (all enum variants inserted in `new()`), that branch is unreachable unless a new variant is added and not added to `new()`.

**Recommendation:** Treat “missing key” as a programming error and fail fast in development, and avoid noisy logging in six places:

- In the increment methods: use `.get().expect("missing ErrorType in ProcessingStats (add variant to new())")` (or similar) so a missing variant panics.
- In the get_* methods: use `.get().unwrap_or(0)` without logging, or the same `.expect(...)` if you prefer to catch missing variants there too. Optionally keep a single `debug_assert!` in one place that all enum lengths match map sizes.

Then remove the defensive `log::error!` / `log::warn!` from all six methods.

---

## 5. `run/mod.rs` (lines 297–383) – tests for JoinSet/tokio behavior

**Location:** `src/run/mod.rs`, `#[cfg(test)] mod tests`

**Finding:** Three tests (`test_joinset_interleaved_reaping`, `test_joinset_handles_panicked_tasks`, `test_joinset_zero_timeout_non_blocking`) primarily exercise `JoinSet` and tokio’s timeout/join behavior. They validate the runtime rather than application logic.

**Recommendation:**

- **Option A:** Remove these three tests and rely on tokio’s own tests and on higher-level tests that exercise `run_scan` (e.g. `test_run_scan_validation_failure`).
- **Option B:** If you keep them, move them to an integration test or a dedicated `tests/joinset_usage.rs` and document that they are “usage contract” tests for our reaping pattern, not unit tests for application behavior.

---

## 6. `error_handling/types.rs` (lines 308–337) – tests for `#[derive(PartialEq)]`

**Location:** `src/error_handling/types.rs`, `test_error_type_equality`, `test_warning_type_equality`, `test_info_type_equality`

**Finding:** These tests only check that `==` and `!=` behave for two values each. That is testing the standard derive of `PartialEq`, not your types’ semantics.

**Recommendation:** Remove these three tests. If you ever change the enums in a way that could break `PartialEq` (e.g. custom impl), you can add a single test that asserts `PartialEq` is implemented (e.g. `fn test_error_type_impls_partial_eq() { let _ = &ErrorType::default() as &dyn std::cmp::PartialEq; }`) or rely on type-check and other tests that use equality.

---

## 7. `error_handling/mod.rs` (line 82) – duplicate `test_processing_stats_initialization`

**Location:** `src/error_handling/mod.rs` (and equivalent logic in `src/error_handling/stats.rs`)

**Finding:** In `error_handling/mod.rs` there is a test `test_processing_stats_initialization` that builds `ProcessingStats::new()` and asserts all error/warning/info counts are 0. In `stats.rs` there is `test_processing_stats_new()` that does the same (all variants zero, plus totals zero). The two tests duplicate the same behavioral contract.

**Recommendation:** Keep a single test that “all counters start at zero” in `stats.rs` (`test_processing_stats_new`). Remove `test_processing_stats_initialization` from `error_handling/mod.rs` to avoid duplication and to keep `ProcessingStats` behavior tested in its own module.

---

## Summary

| # | Issue | Severity | Action |
|---|--------|----------|--------|
| 1 | status_server/error.rs dead code | Low | Use type or consolidate allow(dead_code) + comment |
| 2 | reqwest_ext only in tests | Low | Done: use in production via update_error_stats |
| 3 | config merge overwrites with CLI defaults | **High** | Done: only overwrite when CLI explicitly set; test added |
| 4 | stats defensive logging in 6 methods | Medium | Use expect/unwrap_or, remove redundant logs |
| 5 | run JoinSet tests | Low | Remove or move to integration / usage tests |
| 6 | types PartialEq tests | Low | Remove three tests |
| 7 | Duplicate processing_stats init test | Low | Remove from mod.rs, keep in stats.rs |
