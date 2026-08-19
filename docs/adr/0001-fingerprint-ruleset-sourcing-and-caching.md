# ADR 0001: Fingerprint Ruleset Sourcing and Caching

- Status: Accepted
- Date: 2026-03-01
- Updated: 2026-07-28

## Context

`domain_status` reuses community-maintained technology fingerprints instead of inventing a private ruleset format from scratch. The scanner needs a default source that is:

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
- continue with partial upstream success when at least one configured source loads successfully
- **fall back to a bundled minimal ruleset** (`assets/fingerprints/`, loaded via `src/fingerprint/ruleset/vendored.rs`) when **all** configured sources fail (cold-start offline/CI relief). Remote refresh remains the preferred path when network is available.

When multiple sources are merged, later sources overwrite earlier ones for the same technology key. This is an explicit part of the contract.

## Consequences

Positive:

- avoids maintaining a full first-party fingerprint corpus as the primary source
- keeps the default behavior close to established upstream ecosystems
- supports deterministic local testing by pointing at local rulesets
- amortizes cold-start cost through local caching
- offline/CI first runs no longer hard-fail solely because GitHub is unreachable

Trade-offs:

- cold-cache runs still prefer network when available
- upstream changes can alter detection behavior without local code changes
- partial-source success improves resilience but can reduce consistency if one source is temporarily unavailable
- the vendored fallback is intentionally small (common techs only), not Wappalyzer-complete
- default upstream sources (`enthec/webappanalyzer`, `HTTPArchive/wappalyzer`) are GPL-3.0; see [docs/LICENSES.md](../LICENSES.md)

## Operational Notes

- `GITHUB_TOKEN` is optional but recommended to reduce GitHub API rate-limit issues during metadata lookup
- Fingerprint cache files live under the shared platform cache root (`…/domain_status/fingerprints/`), not the process working directory (see [docs/ADVANCED.md](../ADVANCED.md)). Treat them as regenerable runtime artifacts.
- for fully deterministic CI, prefer an explicit `--fingerprints` path over relying on the vendored fallback

## Related Code

- `src/fingerprint/ruleset/mod.rs`
- `src/fingerprint/ruleset/cache.rs`
- `src/fingerprint/ruleset/vendored.rs`
- `src/fingerprint/ruleset/github/`
- `assets/fingerprints/`
- `docs/PRODUCTION_HARDENING.md`
