# Bundled fingerprint fallback

This directory holds a **minimal** technology fingerprint ruleset in
Wappalyzer-compatible JSON format (`technologies.json`, `categories.json`).

## Purpose

When all configured remote fingerprint sources fail (network unreachable, GitHub
down, etc.), the scanner loads this ruleset at compile time as an offline/CI
fallback. It covers common technologies only and is intentionally **not**
Wappalyzer-complete.

The default path still prefers merging upstream sources; see
[docs/ADVANCED.md](../../docs/ADVANCED.md) and
[ADR 0001](../../docs/adr/0001-fingerprint-ruleset-sourcing-and-caching.md).

## Provenance

These files are a **project-maintained subset** written in the same JSON schema
as upstream Wappalyzer-family projects. They are not a copy of the full
upstream corpus.

The default full ruleset is fetched at runtime from GPL-3.0 upstream repositories
(`enthec/webappanalyzer`, `HTTPArchive/wappalyzer`) and cached under
`…/domain_status/fingerprints/`. For licensing details, see
[docs/LICENSES.md](../../docs/LICENSES.md).
