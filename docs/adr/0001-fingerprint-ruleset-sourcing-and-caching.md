# ADR 0001: Fingerprint Ruleset Sourcing and Caching

- Status: Accepted
- Date: 2026-03-01

## Context

`domain_status` reuses community-maintained technology fingerprints instead of inventing a private ruleset format from scratch. The scanner needs a default source that is:

- good enough for day-to-day scanning
- locally cacheable
- overrideable for deterministic or offline operation
- explicit about merge behavior when more than one upstream is involved

The implementation currently loads rulesets in `src/fingerprint/ruleset/mod.rs`.

## Decision

The scanner will:

- default to merging two upstream technology directories:
  - `enthec/webappanalyzer`
  - `HTTPArchive/wappalyzer`
- cache the resolved ruleset in `.fingerprints_cache/`
- use a cache key derived from the configured source list
- refresh cached rulesets on a 7-day TTL
- allow a caller-supplied local path or URL via `--fingerprints`
- continue with partial upstream success when at least one configured source loads successfully

When multiple sources are merged, later sources overwrite earlier ones for the same technology key. This is an explicit part of the contract.

## Consequences

Positive:

- avoids maintaining a first-party fingerprint corpus
- keeps the default behavior close to established upstream ecosystems
- supports deterministic local testing by pointing at local rulesets
- amortizes cold-start cost through local caching

Trade-offs:

- cold-cache runs can depend on network availability
- upstream changes can alter detection behavior without local code changes
- partial-source success improves resilience but can reduce consistency if one source is temporarily unavailable

## Operational Notes

- `GITHUB_TOKEN` is optional but recommended to reduce GitHub API rate-limit issues during metadata lookup
- the cache is part of the working-directory contract and should be treated as a local runtime artifact

## Related Code

- `src/fingerprint/ruleset/mod.rs`
- `src/fingerprint/ruleset/cache.rs`
- `src/fingerprint/ruleset/github/`
- `docs/PRODUCTION_HARDENING.md`
