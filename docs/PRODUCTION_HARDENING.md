# Production Hardening Guide

This guide documents the runtime behavior that matters in production today. It is intentionally aligned with the current codebase rather than an aspirational future architecture.

## Runtime Profile

`domain_status` is a concurrent, network-heavy batch scanner with SQLite-backed persistence.

During a scan it may:

- open outbound HTTP/S connections
- perform DNS lookups using the system resolver configuration
- optionally perform WHOIS/RDAP lookups
- optionally download and cache fingerprint and GeoIP assets
- write into a local SQLite database in WAL mode
- optionally expose a local-only status server on `127.0.0.1`

## Important Defaults

| Setting | Default | Notes |
|---------|---------|-------|
| Database path | `./domain_status.db` | Scans and exports both default here |
| Max concurrency | `30` | Global worker limit |
| Max per domain | `5` | Set `0` to disable the per-domain cap |
| Initial rate limit | `15` RPS | Adaptive limiter adjusts this when enabled |
| HTTP timeout | `10s` | Request timeout |
| Overall per-URL timeout | `35s` | Guardrail around the full processing pipeline |
| DNS timeout | `3s` | Resolver attempts once and fails fast |
| WHOIS timeout | `5s` | Best-effort enrichment |
| Redirect hop limit | `10` | Prevents loops and excessive chains |
| Response body limit | `2 MiB` | Avoids oversized-body abuse |

## File-System Expectations

The process needs write access to the working directory, or explicit alternate paths, for:

- `./domain_status.db`
- `./domain_status.log` during `scan`
- `…/domain_status/fingerprints/`
- `…/domain_status/geoip/`
- `…/domain_status/whois/`
- `…/domain_status/user_agent/`

Distributed binaries also need a writable temp directory because embedded SQL migrations may be extracted into a temporary directory before execution.

## Database Behavior

### SQLite settings

`init_db_pool_with_path()` currently enables:

- `PRAGMA journal_mode=WAL`
- `PRAGMA synchronous=NORMAL`
- `PRAGMA wal_autocheckpoint=1000`
- `PRAGMA foreign_keys=ON`
- `PRAGMA busy_timeout=5000` (milliseconds; per pooled connection)

These settings are part of the operational contract and should be preserved unless deliberately changed.

### Concurrent writes and the async runtime

SQLite allows concurrent readers in WAL mode but still serializes writers at the database file. Scan tasks insert through a shared `SqlitePool` sized to `--max-concurrency`, so many connections may contend for that single writer lock. Mitigations:

- WAL + `synchronous=NORMAL` for typical scan write patterns
- `busy_timeout` so SQLite waits briefly before returning BUSY
- Pool `acquire_timeout` (5s) so connection waits fail fast
- Application `with_sqlite_retry` for transient `SQLITE_BUSY` / `SQLITE_LOCKED`

Tasks waiting on the pool or lock **park** on async futures; they do not busy-spin Tokio worker threads the way CPU-bound work on an async worker would. Residual risk under extreme insert pile-up is write latency or exhausted retries—not reactor starvation. A dedicated single-writer queue remains a possible future optimization if profiling shows DB writes dominate; see [ADR 0004](adr/0004-sqlite-first-analytical-storage.md).

### Pool sizing

During scans, the SQLite pool is sized to match `--max-concurrency`:

- scan pool size = `max(1, max_concurrency as u32)`

Exports use a smaller fixed pool:

- export pool size = `5`

This means the previous "pool-size mismatch" guidance no longer applies to scan workloads.

### Retention and maintenance

The application does not currently delete old runs automatically. If you retain many historical scans, plan operational cleanup around the `runs` table and use `VACUUM` or WAL checkpoints during maintenance windows.

Example:

```bash
sqlite3 domain_status.db <<'EOF'
DELETE FROM runs
WHERE start_time_ms < (strftime('%s', 'now', '-30 days') * 1000);
VACUUM;
PRAGMA wal_checkpoint(TRUNCATE);
EOF
```

Because many satellite tables use `ON DELETE CASCADE`, deleting old `runs` records also removes most related data.

## Network and Cache Dependencies

### Fingerprint rulesets

By default, scans fetch and merge two upstream technology directories:

- `enthec/webappanalyzer`
- `HTTPArchive/wappalyzer`

The merged ruleset is cached in `…/domain_status/fingerprints/` for 7 days. Cold-cache runs may hit GitHub-hosted assets. Supplying `GITHUB_TOKEN` helps avoid GitHub API rate limits for commit metadata lookups.

### GeoIP

GeoIP is optional and best-effort.

- If `--geoip` is supplied, that path or URL is used.
- Otherwise the scanner attempts an automatic MaxMind download when `MAXMIND_LICENSE_KEY` is set.
- Databases are cached in `…/domain_status/geoip/` for 7 days.
- Failures are logged and scanning continues without GeoIP enrichment.

### WHOIS

WHOIS/RDAP is **on by default**. Disable with `--no-whois` (or `enable_whois = false` in TOML).

- Results are cached in `…/domain_status/whois/` for 7 days.
- Lookup timeout is `5s`.
- Failures are logged and scanning continues.

### User-Agent refresh

If the built-in default User-Agent is used, the scanner may fetch the latest Chrome version and cache it in `…/domain_status/user_agent/version.json` for 30 days. This is a cold-start outbound dependency worth accounting for in locked-down environments.

## Status Server

When `--status-port` is set, the status server:

- binds to `127.0.0.1:<port>`
- exposes `/health`, `/status`, and `/metrics`
- has no authentication
- is intended for local scraping only

`/health` returns 200 OK when the server is up (liveness only; it does not reflect scan success). Do not treat the status server as an internet-facing service. If remote access is required, use an SSH tunnel or a local reverse proxy with explicit access controls.

## Observability Signals

The live status endpoints expose progress and runtime health for long-running scans:

- attempted / pending / active URLs
- successful / failed / skipped URLs (aligned with finalize and the `runs` table)
- finished vs dispatched percentage
- lifetime and windowed throughput, plus ETA
- scan phase (`scanning` / `draining` / `finalizing`)
- configured RPS limit (`current_rps`) and concurrency in use
- retry counts and non-retriable failure counts
- average timing metrics for major processing stages

If you monitor production scans, prefer scraping `/metrics` and alerting on:

- sustained low measured throughput (`domain_status_rate_per_second` / `domain_status_windowed_rate_per_second`) relative to configured `domain_status_current_rps`
- growth in `domain_status_runtime_non_retriable_failures_total`
- unexpected growth in `domain_status_failed_urls` or `domain_status_skipped_urls`

For fleet or multi-instance runs, `domain_status_run_info{run_id="..."}`, `domain_status_elapsed_seconds`, and `domain_status_start_time_seconds` let you correlate metrics with a specific scan run (e.g. in the database or logs) and build time-based dashboards.

The status server is scan-scoped: it shuts down during finalize. Use SQLite / `ScanReport` for post-run truth.

## Failure Policy Guidance

Choose `--fail-on` deliberately:

- `never`: data-collection mode, never fails the process because of scan failures
- `any-failure`: strict mode for small, high-confidence target sets
- `pct>` with `--fail-on-pct-threshold`: useful for large batches where some failures are expected

Remember that `pct>` returns exit code `3` when zero URLs were processed.

## Hardening Checklist

- Run from a directory with predictable write access, or override paths explicitly.
- Pre-warm `…/domain_status/fingerprints/` and `…/domain_status/geoip/` in controlled environments if cold-start network access is undesirable.
- Provide `GITHUB_TOKEN` when relying on default GitHub-hosted fingerprint sources.
- Provide `MAXMIND_LICENSE_KEY` only when GeoIP is required.
- Keep the status server local-only.
- Plan retention and SQLite maintenance for large historical datasets.
- Monitor runtime retry metrics and failed/skipped rates on long-running scans.
