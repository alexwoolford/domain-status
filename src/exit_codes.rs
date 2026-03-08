//! Named exit codes for the `domain_status` binary.
//!
//! These constants are the single source of truth for process exit codes.
//! See [`docs/EXIT_CODES.md`](../../docs/EXIT_CODES.md) for full semantics.

/// Exit code for successful completion, or when failures are ignored by policy (`--fail-on never`).
pub const EXIT_SUCCESS: i32 = 0;

/// Exit code for CLI/configuration/initialization or other runtime error before policy evaluation.
pub const EXIT_RUNTIME_ERROR: i32 = 1;

/// Exit code when the selected failure policy is exceeded (`--fail-on any-failure` or `--fail-on pct>`).
pub const EXIT_POLICY_FAILURE: i32 = 2;

/// Exit code when `--fail-on pct>` was selected but zero URLs were processed.
pub const EXIT_NO_URLS_PCT: i32 = 3;
