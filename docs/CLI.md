# CLI cheat sheet

Full flag help: `domain_status --help`, `domain_status scan --help`, etc.

## Commands

```bash
domain_status scan <urls.txt|->     # Scan → SQLite
domain_status summary               # Last (or --run-id) run digest
domain_status export                # Optional flatten (csv|jsonl|parquet)
```

## How to configure

Four surfaces, two jobs (plus a local seed):

| Surface | Job |
|---------|-----|
| **CLI flags** | Day-to-day / one-off overrides |
| **TOML** | Repeatable job profile (checked in, shared) |
| **`DOMAIN_STATUS_*` env** | Containers, CI, systemd |
| **`.env`** | Local convenience that *only* seeds process env — **not** a separate merge tier |

Prefer **one** job style per deployment (TOML *or* env); use CLI to override. Do not put secrets in TOML.

**Precedence:** `CLI flags` > `DOMAIN_STATUS_*` env (via clap) > TOML file > defaults.

- Config file path: `--config` **wins** over `DOMAIN_STATUS_CONFIG_FILE`; else cwd `domain_status.toml` if present.
- `.env` (cwd, else next to the binary) loads before clap runs; it does not override already-set env vars.
- Secrets stay env / `.env` only: `MAXMIND_LICENSE_KEY`, `GITHUB_TOKEN` (no CLI flags).

## Scan config matrix

| Flag | Env | TOML key | Default |
|------|-----|----------|---------|
| positional `file` | — | `file` (library/TOML only; CLI requires the positional) | `urls.txt` (library) |
| `--config` | `DOMAIN_STATUS_CONFIG_FILE` | — | cwd `domain_status.toml` if present |
| `--db-path` | `DOMAIN_STATUS_DB_PATH` | `db_path` | `./domain_status.db` |
| `--log-file` | `DOMAIN_STATUS_LOG_FILE` | `log_file` | `domain_status.log` |
| `--log-level` | `DOMAIN_STATUS_LOG_LEVEL` | `log_level` | `info` |
| `-v` / `-q` | — | — | Info baseline (overrides `--log-level`) |
| `--log-format` | `DOMAIN_STATUS_LOG_FORMAT` | `log_format` | `plain` |
| `--max-concurrency` | `DOMAIN_STATUS_MAX_CONCURRENCY` | `max_concurrency` | `30` |
| `--timeout-seconds` | `DOMAIN_STATUS_TIMEOUT_SECONDS` | `timeout_seconds` | `10` |
| `--user-agent` | `DOMAIN_STATUS_USER_AGENT` | `user_agent` | Chrome UA (auto-refresh if default) |
| `--rate-limit-rps` | `DOMAIN_STATUS_RATE_LIMIT_RPS` | `rate_limit_rps` | `15` (`0` disables) |
| `--fingerprints` | `DOMAIN_STATUS_FINGERPRINTS` | `fingerprints` | GitHub defaults |
| `--geoip` | `DOMAIN_STATUS_GEOIP` | `geoip` | off (or MaxMind auto via license) |
| `--status-port` | `DOMAIN_STATUS_STATUS_PORT` | `status_port` | off |
| `--enable-whois` | `DOMAIN_STATUS_ENABLE_WHOIS` | `enable_whois` | **on** (legacy flag; redundant with the default) |
| `--no-whois` | — | — | Force-disable WHOIS |
| `--no-progress` | `DOMAIN_STATUS_NO_PROGRESS` | — | Hide the TTY progress bar (log file still records progress) |
| `--cache-dir` | `DOMAIN_STATUS_CACHE_DIR` | `cache_dir` | platform cache + `domain_status/` |
| `--scan-external-scripts` | `DOMAIN_STATUS_SCAN_EXTERNAL_SCRIPTS` | `scan_external_scripts` | off |
| `--fail-on` | `DOMAIN_STATUS_FAIL_ON` | `fail_on` | `never` (`any-failure` \| `pct>`) |
| `--fail-on-pct-threshold` | `DOMAIN_STATUS_FAIL_ON_PCT_THRESHOLD` | `fail_on_pct_threshold` | `10` |
| `--drain-timeout-secs` | `DOMAIN_STATUS_DRAIN_TIMEOUT_SECS` | `drain_timeout_secs` | `10` |

TOML/`DOMAIN_STATUS_FAIL_ON` also accept `any_failure` / `anyfailure` as aliases of `any-failure`.

## Export / summary

Mostly CLI-only (plus shared `--db-path` / `DOMAIN_STATUS_DB_PATH`):

```bash
domain_status summary                  # digest for latest run; --top N (default 15)
domain_status summary --top 20         # list more top technologies
domain_status export --format csv --output results.csv
domain_status export --format jsonl --run-id run_…
domain_status export --domain example.com --status 200 --since 1700000000000
domain_status export --include-implied-tech   # include is_implied=1 fingerprint rows (off by default)
```

Export filters (optional): `--domain` (substring match on final domain), `--status` (HTTP status code), `--since` (epoch ms lower bound on `observed_at_ms`), `--run-id`.

### Stdout / stderr

- **Diagnostics** (logs, progress, scan/export banners) go to **stderr**, or to the scan `--log-file` when the progress bar is active. The logger uses `env_logger` with `Target::Stderr` on export/summary.
- **Machine-readable export data** goes to **stdout** only when you pass `--output -` (CSV or JSONL). Otherwise export writes a file (`domain_status_export.{csv|jsonl|parquet}` by default).
- Pipe-friendly example:

```bash
domain_status export --format jsonl --output - | jq .
```

Stderr still shows version INFO and “Exported N records”; silence with `2>/dev/null` if needed. Log lines are not mixed into the JSONL/CSV stream.

See [ADVANCED.md](ADVANCED.md) for enrichments and cache layout.
