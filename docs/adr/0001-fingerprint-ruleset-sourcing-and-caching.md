# ADR 0001: Fingerprint Ruleset Sourcing and Caching

- Status: Accepted
- Date: 2026-03-01
- Updated: 2026-09-17

## Context

`domain-status` reuses community-maintained technology fingerprints instead of inventing a private ruleset format from scratch. The scanner needs a default source that is:

- good enough for day-to-day scanning
- locally cacheable
- overrideable for deterministic or offline operation
- explicit about merge behavior when more than one upstream is involved
- able to start in offline/CI environments when remotes are unreachable

The implementation currently loads rulesets in `src/fingerprint/ruleset/mod.rs`.

## Decision

The scanner will:

- default to merging two upstream technology directories:
  - `enthec/webappanalyzer`
  - `HTTPArchive/wappalyzer`
- cache the resolved ruleset under the shared cache root (`…/domain_status/fingerprints/`)
- use a cache key derived from the configured source list
- refresh cached rulesets on a 7-day TTL
- allow a caller-supplied local path or URL via `--fingerprints`
- **abort the default scan** when either default remote fails or the merged catalog has fewer than 1000 technologies
- **fall back to a bundled minimal ruleset** (`assets/fingerprints/`, loaded via `src/fingerprint/ruleset/vendored.rs`) only with `--allow-degraded-fingerprints` (or an explicit `--fingerprints` path). Remote refresh remains the preferred path when network is available.
- **apply a first-party overlay** (`assets/fingerprints/overlay.json`) last, after upstream merge, cache load, or vendored fallback, so project-specific rules (Payload, tightened Amazon S3) do not require forking the corpus

When multiple sources are merged, later sources overwrite earlier ones for the same technology key. The overlay then overwrites those. This is an explicit part of the contract.

## Consequences

Positive:

- avoids maintaining a full first-party fingerprint corpus as the primary source
- keeps the default behavior close to established upstream ecosystems
- supports deterministic local testing by pointing at local rulesets
- amortizes cold-start cost through local caching
- default Homebrew scans cannot silently run on bundled-minimal after a GitHub failure

Trade-offs:

- cold-cache runs still prefer network when available
- upstream changes can alter detection behavior without local code changes
- partial-source success improves resilience but can reduce consistency if one source is temporarily unavailable
- the vendored fallback is intentionally small (common techs only), not Wappalyzer-complete
- default upstream sources (`enthec/webappanalyzer`, `HTTPArchive/wappalyzer`) are GPL-3.0; see [docs/LICENSES.md](../LICENSES.md)

## Operational Notes

- `GITHUB_TOKEN` is optional rate-limit headroom (60 → 5000 requests/hour), not a requirement for the full catalog. Mention it in logs only when a fetch actually hit the GitHub API rate limit. A 401 Bad credentials response retries the listing unauthenticated.
- Fingerprint cache files live under the shared platform cache root (`…/domain_status/fingerprints/`), not the process working directory (see [docs/ADVANCED.md](../ADVANCED.md)). Treat them as regenerable runtime artifacts.
- for fully deterministic CI, prefer an explicit `--fingerprints` path over relying on the vendored fallback

## Related Code

- `src/fingerprint/ruleset/mod.rs`
- `src/fingerprint/ruleset/cache.rs`
- `src/fingerprint/ruleset/vendored.rs`
- `src/fingerprint/ruleset/overlay.rs`
- `src/fingerprint/ruleset/github/`
- `assets/fingerprints/`
- `assets/fingerprints/overlay.json`
- `docs/PRODUCTION_HARDENING.md`
