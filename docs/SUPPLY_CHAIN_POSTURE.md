# Supply Chain Posture

This document summarizes dependency and CI practices for supply chain security.

**Last reviewed:** 2026-07-23 (dependency cleanup: version policy, parquet 59 / thrift removal, whois-service unvendor).

---

## Dependency version policy

- **Manifest reqs (`Cargo.toml` / `cli/Cargo.toml`):** use caret minor precision — `^X.Y` — not patch pins (`1.2.3` / `0.18.4`). Cargo’s `"1.2"` and `"^1.2"` are equivalent; prefer the explicit `^` form for consistency.
- **`Cargo.lock`:** commit exact resolved versions. That is the reproducibility source of truth.
- **Workspace / path crates:** keep exact versions aligned with the package (`domain_status_cli = "0.1.x"`).
- **Majors and breaking 0.x bumps:** Dependabot ignores `semver-major`. Land those in intentional PRs (with `just check` / audit / deny).
- **Exceptions (documented in-manifest):**
  - `murmur3 = "^0.1"` — Shodan-compatible favicon hashes; do not bump to 0.5 without golden-hash proof.
  - `reqwest = "^0.12"` — 0.13 deferred (TLS / redirect / whois alignment surface).

---

## CI: cargo audit and cargo deny

- **Security job** (`.github/workflows/ci.yml`): Runs on push, pull_request, and weekly schedule.
  - `cargo audit` — checks dependencies against the RustSec advisory database (CVE and RUSTSEC).
  - `cargo deny check advisories bans sources` — enforces [deny.toml](deny.toml) (advisories, duplicate/wildcard bans, registry sources).
- **Action pinning:** Workflow actions use version tags (for example `actions/checkout@v6`, `dtolnay/rust-toolchain@stable`). Prefer deliberate upgrades of those tags; full-commit SHA pinning is not currently required.

---

## deny.toml policy

- **Advisories:** `yanked = "deny"`. One advisory explicitly ignored: `RUSTSEC-2024-0436` (`paste`, still pulled by `parquet` 59) until upstream replaces it.
- **Bans:** `multiple-versions = "warn"`, `wildcards = "deny"`, `highlight = "all"`.
- **Sources:** Only `https://github.com/rust-lang/crates.io-index` allowed; unknown registries and unknown git sources denied.

---

## .cargo/audit.toml

- **Ignores:** `RUSTSEC-2023-0071` (`rsa`) — present in `Cargo.lock` via `sqlx` → `sqlx-mysql` resolution even with sqlite-only features; not linked into the binary. No fixed rsa release yet.
- `RUSTSEC-2024-0436` (`paste`) is handled in `deny.toml` (parquet transitive).
- Revisit when upgrading `sqlx` or `parquet`; remove ignores when no longer applicable.

---

## Cargo.toml and dependencies

- **TLS:** reqwest is used with `default-features = false` and `features = ["rustls-tls", ...]` — no native TLS.
- **WHOIS:** `whois-service` `^0.3` from crates.io (`default-features = false`). The former `vendor/whois-service` patch (0.2.1) was removed once 0.3.0 stopped pulling `rustls-pemfile`.
- **Parquet/Arrow:** `arrow` / `parquet` `^59`. Parquet 59 drops the `thrift` crate dependency (the previous Dependabot thrift ignore is no longer needed). `paste` remains transitive until upstream removes it.
- **Large/analytical crates:** arrow/parquet are used for export only; they add size and the `paste` advisory ignore. Acceptable for the feature; keep deny ignores documented and minimal.

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
