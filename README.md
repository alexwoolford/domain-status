# domain_status

[![Crates.io](https://img.shields.io/crates/v/domain_status)](https://crates.io/crates/domain_status)
[![docs.rs](https://img.shields.io/docsrs/domain_status)](https://docs.rs/domain_status)
[![Downloads](https://img.shields.io/crates/d/domain_status)](https://crates.io/crates/domain_status)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.86+-orange.svg)](https://www.rust-lang.org/)
[![CI](https://github.com/alexwoolford/domain_status/actions/workflows/ci.yml/badge.svg)](https://github.com/alexwoolford/domain_status/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/alexwoolford/domain_status?label=latest%20release)](https://github.com/alexwoolford/domain_status/releases/latest)

**domain_status** is a concurrent URL/domain scanner. Give it a list of URLs; it captures HTTP status, TLS certificates, DNS, technology fingerprints, and related signals in one pass, and stores results in **SQLite** for relational analysis (1:many satellites for technologies, secrets, redirects, DNS rows, and more). Export the same run to Parquet or JSONL when you want DuckDB / data-lake workflows or shell pipelines—SQLite remains the source of truth.

**Who it's for:** DevOps/SRE, security analysts, threat-intel / OSINT researchers, light-touch tech diligence / portfolio intelligence (e.g. PE ops), and anyone managing large URL/domain portfolios who wants one tool instead of stitching curl, whois, and Wappalyzer together.

## Quick Start

```bash
# Install (macOS/Linux)
brew tap alexwoolford/domain-status && brew install domain_status
# or: cargo install domain_status
# or: download a binary from Releases

echo -e "https://example.com\nhttps://example.org" > urls.txt
domain_status scan urls.txt

# Convenience digest (same DB)
domain_status summary

# SQLite is the primary result store (1:many joins are intentional)
sqlite3 domain_status.db "SELECT initial_domain, http_status, title FROM url_status;"
sqlite3 domain_status.db "SELECT technology_name, COUNT(*) AS n FROM url_technologies WHERE is_implied = 0 GROUP BY 1 ORDER BY n DESC LIMIT 20;"
sqlite3 domain_status.db "SELECT secret_type, severity, COUNT(*) FROM url_exposed_secrets GROUP BY 1, 2 ORDER BY 3 DESC;"
```

More SQL: [QUERIES.md](QUERIES.md) and [DATABASE.md](DATABASE.md).

**Optional exports** (from the same SQLite DB—lossy flatten vs full schema for CSV/JSONL):

```bash
# Shell tooling (payload on stdout; logs/banners on stderr — see docs/CLI.md)
domain_status export --format jsonl --output - | jq '.final_domain, .technologies'

# Columnar analytics (e.g. DuckDB: SELECT * FROM 'recon.parquet')
domain_status export --format parquet --output recon.parquet
```

CSV: `domain_status export --format csv`. Everyday flags: `domain_status scan -h`. All flags: `--help`.

WHOIS is on by default (`--no-whois` to disable). GeoIP needs `MAXMIND_LICENSE_KEY` or `--geoip`. First-party script bodies: `--scan-external-scripts`. Local fingerprint rules, caches, and GitHub-free ruleset loading: [docs/ADVANCED.md](docs/ADVANCED.md).

## Features (core)

- HTTP status, redirects, response metadata
- TLS certificate fields (resolves all public IPs, IPv4-first, so dual-stack hosts with broken IPv6 egress still get a certificate)
- DNS (NS/TXT/MX + SPF/DMARC/MTA-STS/TLS-RPT/BIMI), parsed HSTS, CDN taxonomy, `security.txt` / `robots.txt`
- Technology fingerprints + exposed secrets (static analysis; no JS execution). Fingerprints use headers/cookies/meta/HTML/`scriptSrc` URLs/inline script text/DNS/cert issuer from the initial response. With `--scan-external-scripts`, first-party fetched script bodies also feed secret detection and Wappalyzer `scripts` tech patterns.
- Security signals are **query-derived** (no `url_security_warnings` table): e.g. non-HTTPS finals, weak TLS versions, self-signed/mismatched/expired certs. Header *presence* (HSTS/CSP/etc.) is stored; "missing header" is a query, not a precomputed warning — see [DATABASE.md](DATABASE.md) and [QUERIES.md](QUERIES.md) §30
- SQLite fact table + satellite tables; `summary` command
- Concurrency / rate limiting; `--fail-on` for CI exit policy

**Also available (see docs):** GeoIP, WHOIS, live status/Prometheus server, CSV/JSONL/Parquet export, TOML/`DOMAIN_STATUS_*` config.

## Limitations

- Static analysis only — no JavaScript rendering; JS-runtime-only fingerprint rules will not match
- Fingerprint *rules* depend on GitHub refresh, cache, or a local `--fingerprints` path (target scans still need network)
- Private/link-local targets are blocked (SSRF protection)

## Configuration (keep it simple)

**Day-to-day:** CLI flags (`domain_status scan -h`; all flags: `scan --help`). Prefer `-v` / `-q` for log verbosity.

**Repeatable jobs:** pick **one** of TOML (`--config ./domain_status.toml` or cwd `domain_status.toml`) **or** `DOMAIN_STATUS_*` env for the job profile; use CLI only to override. Mixing TOML and env for the same knobs works (env wins) but is harder to reason about. **`--config` wins** over `DOMAIN_STATUS_CONFIG_FILE`.

**Local secrets:** put `MAXMIND_LICENSE_KEY` / `GITHUB_TOKEN` in `.env` or the real environment — never in TOML. `.env` only seeds process env; it is not a fifth precedence tier.

Precedence: CLI > `DOMAIN_STATUS_*` > TOML > defaults. Details: [docs/CLI.md](docs/CLI.md).

Example TOML: [`config_examples/domain_status.example.toml`](config_examples/domain_status.example.toml).

## Documentation

| Doc | Purpose |
|-----|---------|
| [docs/CLI.md](docs/CLI.md) | Command cheat sheet (`scan` / `summary` / `export`) |
| [docs/ADVANCED.md](docs/ADVANCED.md) | GeoIP, WHOIS, fingerprints, status server, caches, tuning |
| [DATABASE.md](DATABASE.md) | Full schema |
| [QUERIES.md](QUERIES.md) | SQL cookbook |
| [docs/EXIT_CODES.md](docs/EXIT_CODES.md) | CI exit policies |
| [docs.rs/domain_status](https://docs.rs/domain_status) | Library / embed API |
| [CONTRIBUTING.md](CONTRIBUTING.md) / [docs/DEVELOPER_BOOTSTRAP.md](docs/DEVELOPER_BOOTSTRAP.md) | Development |

## License

MIT for this codebase — see [LICENSE](LICENSE). For Rust dependencies and
optional runtime data (fingerprints, gitleaks rules, MaxMind), see
[docs/LICENSES.md](docs/LICENSES.md).
