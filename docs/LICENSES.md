# Licensing overview

This page explains how licensing works in `domain_status`. There are three
separate layers: the project license, Rust crate dependencies, and optional
runtime or bundled data. They are checked differently and should not be
confused.

This document is factual guidance for developers, not legal advice. If you
redistribute binaries or need compliance sign-off, review fingerprint and GeoIP
terms separately from the MIT project license.

## This project

The `domain_status` Rust codebase (including `domain_status_cli`) is licensed
under the **MIT License**. See [LICENSE](../LICENSE).

The license is declared in [`Cargo.toml`](../Cargo.toml) and
[`cli/Cargo.toml`](../cli/Cargo.toml), and matches the release packaging in
`.github/workflows/release.yml`.

## Rust dependencies

Third-party crates from crates.io are governed by a **dependency allowlist** in
[`deny.toml`](../deny.toml), enforced by [cargo-deny](https://embarkstudios.github.io/cargo-deny/)
via `just deny` in CI.

That allowlist is **not** the project license. It answers: which SPDX licenses
may appear in the dependency graph?

The policy permits common permissive licenses only. In practice the graph is
dominated by **MIT** and **Apache-2.0** (many crates are dual-licensed as MIT
OR Apache-2.0, so cargo-deny may report both). Other families in use include
**BSD**, **ISC**, **Zlib**, **Unlicense**, **Unicode-3.0**, **CDLA-Permissive-2.0**,
and **MPL-2.0** (file-level copyleft via the HTML parsing stack, e.g.
`scraper` / `cssparser`). There is **no GPL** in the crate graph.

cargo-deny does **not** audit non-crate data (fingerprint JSON, gitleaks rules,
MaxMind databases). See the sections below.

## Technology fingerprints

By default the scanner merges technology definitions from two upstream GitHub
repositories (see [ADR 0001](adr/0001-fingerprint-ruleset-sourcing-and-caching.md)):

- [enthec/webappanalyzer](https://github.com/enthec/webappanalyzer) — GPL-3.0
- [HTTPArchive/wappalyzer](https://github.com/HTTPArchive/wappalyzer) — GPL-3.0

The merged ruleset is downloaded at runtime, cached under
`…/domain_status/fingerprints/`, and refreshed on a 7-day TTL. The full upstream
corpus is **not** shipped in this repository.

For deterministic or fully offline operation, pass `--fingerprints` with a local
path or URL. See [ADVANCED.md](ADVANCED.md).

When all configured remote sources fail, the scanner falls back to a **bundled
minimal ruleset** in [`assets/fingerprints/`](../assets/fingerprints/). That
subset is project-maintained, Wappalyzer-compatible JSON — not a full upstream
dump. See [assets/fingerprints/README.md](../assets/fingerprints/README.md).

This pattern (MIT application code, GPL fingerprint data fetched at runtime) is
common in the ecosystem; see for example
[wappalyzergo](https://github.com/projectdiscovery/wappalyzergo).

## Other bundled and optional data

### Gitleaks secret-detection rules

Secret scanning uses a bundled [`config/gitleaks.toml`](../config/gitleaks.toml)
(loaded in `src/parse/gitleaks.rs`). The upstream
[gitleaks](https://github.com/gitleaks/gitleaks) project is **MIT**. Web-specific
overrides live in
[`config/gitleaks.overrides.toml`](../config/gitleaks.overrides.toml).

### MaxMind GeoLite2

GeoIP enrichment is optional. When enabled via `MAXMIND_LICENSE_KEY` or
`--geoip`, the scanner may download MaxMind GeoLite2 data subject to the
[MaxMind GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula). See
[ADVANCED.md](ADVANCED.md).
