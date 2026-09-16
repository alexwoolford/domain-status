# Supply Chain Posture

This document summarizes dependency and CI practices for supply chain security.

**Last reviewed:** 2026-09-15 (`whois-service` remains `[patch.crates-io]` / `vendor/whois-service` until crates.io disables reqwest default-tls).

---

## Dependency version policy

- **Manifest reqs (`Cargo.toml` / `cli/Cargo.toml`):** use caret minor precision — `^X.Y` — not patch pins (`1.2.3` / `0.18.4`). Cargo’s `"1.2"` and `"^1.2"` are equivalent; prefer the explicit `^` form for consistency.
- **`Cargo.lock`:** commit exact resolved versions. That is the reproducibility source of truth.
- **Workspace / path crates:** keep exact versions aligned with the package (`domain-status-cli` / `0.2.0`).
- **Majors and breaking 0.x bumps:** Dependabot ignores `semver-major`. Land those in intentional PRs (with `just check` / audit / deny).
- **Exceptions (documented in-manifest):**
  - `reqwest = "^0.12"` — 0.13 deferred until `whois-service` (crates.io and `vendor/whois-service`) can move with it (TLS / redirect alignment). Do not mix that bump with SQLx.

---

## CI: cargo audit and cargo deny

- **Security job** (`.github/workflows/ci.yml`): Runs on push, pull_request, and weekly schedule.
  - `cargo audit` — checks dependencies against the RustSec advisory database (CVE and RUSTSEC).
  - `cargo deny check advisories bans sources` — enforces [deny.toml](deny.toml) (advisories, duplicate/wildcard bans, registry sources).
- **Action pinning:** Workflow actions use version tags (for example `actions/checkout@v6`, `dtolnay/rust-toolchain@stable`). Prefer deliberate upgrades of those tags; full-commit SHA pinning is not currently required.

---

## deny.toml policy

- **Advisories:** `yanked = "deny"`. No crate-specific ignores in `deny.toml` today (`paste` / RUSTSEC-2024-0436 is gone from the lockfile as of parquet 59).
- **Bans:** `multiple-versions = "warn"`, `wildcards = "deny"`, `highlight = "all"`.
- **Sources:** Only `https://github.com/rust-lang/crates.io-index` allowed; unknown registries and unknown git sources denied.

---

## .cargo/audit.toml

- **Ignores:** none. SQLx 0.9 dropped the `rsa` crate from the resolved graph (`cargo tree -i rsa` is empty); `RUSTSEC-2023-0071` is no longer ignored.
- Revisit when upgrading `sqlx` or `parquet`; remove ignores that no longer apply.

---

## Cargo.toml and dependencies

- **TLS:** reqwest is used with `default-features = false` and `features = ["rustls-tls", ...]` — no native TLS. `whois-service` 0.3.0 from crates.io still enables reqwest `default-tls`; `[patch.crates-io]` overlays `vendor/whois-service` so RDAP uses rustls-only reqwest (`cargo tree -i native-tls` empty).
- **WHOIS:** `whois-service` `^0.3` (`default-features = false`, no HTTP server). Patch is a one-line reqwest TLS change on 0.3.0; drop it when upstream disables reqwest defaults.
- **Parquet/Arrow:** `arrow` / `parquet` `^59`. Parquet 59 drops the `thrift` crate dependency. `paste` is no longer in `Cargo.lock`.
- **Large/analytical crates:** arrow/parquet are used for export only; they add binary size. Acceptable for the feature.
- **config / toml:** `config` `^0.15` (default-features off, `toml` only) matches vendored whois-service; `toml` `^1` preserves table key order (needed for gitleaks overlay association).
- **murmur3:** `^0.5` for Shodan-compatible favicon hashes. Golden hashes in `src/fetch/favicon.rs` pin bit-identical output vs 0.1.
- **Retry:** exponential backoff lives in `src/error_handling/categorization.rs` (no `tokio-retry`).
- **SQLx:** `^0.9` with `default-features = false`, `sqlite-bundled`, `runtime-tokio`, `tls-rustls-aws-lc-rs`, `migrate`. Do not enable the `sqlite` meta-feature (it turns on `sqlite-load-extension`). Dynamic SQL uses `sqlx::AssertSqlSafe` via `src/sql.rs`. `sqlx-mysql` / `sqlx-postgres` may still appear in `Cargo.lock` as sqlx package metadata; they are not activated.

---

## Dependabot

- Weekly cargo updates; patch and minor groups; majors ignored for automated PRs.
- Codecov: project and patch status are disabled in [`codecov.yml`](../codecov.yml) so coverage noise does not fail dependency PRs. Confirm GitHub/Codecov app settings do not re-require `codecov/project`.

---

## Recommendations

1. **Keep** running `cargo audit` and `cargo deny` in CI on every push/PR and on a weekly schedule.
2. **Review** deny/audit ignores when upgrading parquet or sqlx; remove ignores that no longer apply.
3. **Do not** add wildcard dependencies or new registries without updating deny.toml and documenting the reason.
4. **Upgrade** GitHub Actions tags deliberately (checkout, rust-toolchain, gitleaks-action, codecov); consider full-SHA pins only if threat model requires it.
5. **Prefer** controlled cleanup PRs over stacking many Dependabot minors when changing version policy or dropping transitive crates (e.g. thrift).
6. **Defer** reqwest 0.13 until the vendored `whois-service` reqwest pin can move in the same change.
