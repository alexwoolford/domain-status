# Supply Chain Posture

This document summarizes dependency and CI practices for supply chain security.

**Last reviewed:** 2026-03-01 (Security Posture Report implementation).

---

## CI: cargo audit and cargo deny

- **Security job** (`.github/workflows/ci.yml`): Runs on push, pull_request, and weekly schedule.
  - `cargo audit` — checks dependencies against the RustSec advisory database (CVE and RUSTSEC).
  - `cargo deny check advisories bans sources` — enforces [deny.toml](deny.toml) (advisories, duplicate/wildcard bans, registry sources).
- **Action pinning:** All workflow actions are pinned by full commit SHA (see Release Engineering and CI refactor). This avoids supply chain risk from tag movement or compromised action repos.

---

## deny.toml policy

- **Advisories:** `yanked = "deny"`. One advisory explicitly ignored: `RUSTSEC-2024-0436` (paste, via parquet) until upstream replaces it.
- **Bans:** `multiple-versions = "warn"`, `wildcards = "deny"`, `highlight = "all"`.
- **Sources:** Only `https://github.com/rust-lang/crates.io-index` allowed; unknown registries and unknown git sources denied.

---

## .cargo/audit.toml

- **Ignores:** A small set of advisories is ignored with comments:
  - `RUSTSEC-2023-0071` — native-tls; we use rustls-only reqwest.
  - `RUSTSEC-2025-0057` — fxhash (transitive via scraper/selectors).
  - `RUSTSEC-2025-0134` — rustls-pemfile (in reqwest/rustls stack); documented for removal when upstream moves.
- These should be revisited when dependencies are upgraded; remove ignores when no longer applicable.

---

## Cargo.toml and dependencies

- **TLS:** reqwest is used with `default-features = false` and `features = ["rustls-tls", ...]` — no native TLS. Reduces attack surface and avoids native-tls advisories.
- **Vendored patch:** `whois-service` is patched via `[patch.crates-io]` to a local `vendor/whois-service` build (reqwest 0.12) to align TLS and avoid pulling vulnerable rustls-pemfile where possible. The patch is versioned and reviewed with the rest of the tree.
- **Large/analytical crates:** arrow/parquet are used for export only; they add size and transitive advisories (e.g. paste). Acceptable for the feature; keep deny/audit ignores documented and minimal.

---

## Recommendations

1. **Keep** running `cargo audit` and `cargo deny` in CI on every push/PR and on a weekly schedule.
2. **Review** `.cargo/audit.toml` ignores when upgrading reqwest, rustls, scraper, or parquet; remove ignores that no longer apply.
3. **Do not** add wildcard dependencies or new registries without updating deny.toml and documenting the reason.
4. **Preserve** action SHA pinning in all workflows; update SHAs deliberately when upgrading actions.
