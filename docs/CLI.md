# CLI cheat sheet

Full flag help: `domain_status --help`, `domain_status scan --help`, etc.

## Commands

```bash
domain_status scan <urls.txt|->     # Scan → SQLite
domain_status summary               # Last (or --run-id) run digest
domain_status export                # Optional flatten (csv|jsonl|parquet)
```

## Scan essentials

| Flag | Default | Notes |
|------|---------|--------|
| `--db-path` | `./domain_status.db` | Primary output |
| `--log-file` | `domain_status.log` | Scan log (progress bar uses stderr) |
| `-v` / `-q` | Info baseline | Preferred verbosity; overrides `--log-level` when set |
| `--log-level` | `info` | Baseline when not using `-v`/`-q` |
| `--log-format` | `plain` | Format of `--log-file` (`plain` or `json`) |
| `--max-concurrency` | `30` | Cap 500 |
| `--rate-limit-rps` | `15` | `0` disables |
| `--timeout-seconds` | `10` | Per-request HTTP timeout (per-URL budget is separate, 35s) |
| `--cache-dir` | XDG / env | Shared root for fingerprints/geoip/whois/UA |
| `--fingerprints` | GitHub defaults | Local path or URL |
| `--geoip` | off | Path/URL; or `MAXMIND_LICENSE_KEY` auto-download |
| `--enable-whois` | off | Opt-in |
| `--no-whois` | — | Force-disable if TOML enabled WHOIS |
| `--fail-on` | `never` | `any-failure` \| `pct>` (+ `--fail-on-pct-threshold`) |
| `--status-port` | off | Local Axum `/health` `/status` `/metrics` |
| `--drain-timeout-secs` | `10` | Abort in-flight after queue drain |
| `--scan-external-scripts` | off | First-party script **secret** scan (does not feed technology fingerprints) |

## Config precedence

`CLI flags` > `DOMAIN_STATUS_*` env (and clap-bound env) > TOML file > defaults.

Config file path: `--config` **wins** over `DOMAIN_STATUS_CONFIG_FILE`; else cwd `domain_status.toml` if present.

## Export / summary

```bash
domain_status summary --top 20
domain_status export --format csv --output results.csv
domain_status export --format jsonl --run-id run_…
domain_status export --include-implied-tech   # include is_implied=1 fingerprint rows (off by default)
```

See [ADVANCED.md](ADVANCED.md) for enrichments and cache layout.
