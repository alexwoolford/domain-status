# domain_status

[![Crates.io](https://img.shields.io/crates/v/domain_status)](https://crates.io/crates/domain_status)
[![docs.rs](https://img.shields.io/docsrs/domain_status)](https://docs.rs/domain_status)
[![Downloads](https://img.shields.io/crates/d/domain_status)](https://crates.io/crates/domain_status)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85+-orange.svg)](https://www.rust-lang.org/)
[![CI](https://github.com/alexwoolford/domain_status/actions/workflows/ci.yml/badge.svg)](https://github.com/alexwoolford/domain_status/actions/workflows/ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/alexwoolford/domain_status?label=latest%20release)](https://github.com/alexwoolford/domain_status/releases/latest)

**domain_status** is a concurrent URL/domain scanner. Give it a list of URLs; it captures HTTP status, TLS certificates, DNS, technology fingerprints, and related signals in one pass, and stores results in **SQLite** for relational analysis (1:many satellites for technologies, secrets, redirects, DNS rows, and more).

**Who it's for:** DevOps/SRE, security analysts, and anyone managing large URL/domain portfolios who wants one tool instead of stitching curl, whois, and Wappalyzer together.

## Quick Start

```bash
# Install (macOS/Linux)
brew tap alexwoolford/domain-status && brew install domain_status
# or: cargo install domain_status
# or: download a binary from Releases

echo -e "https://example.com\nhttps://example.org" > urls.txt
domain_status scan urls.txt
domain_status summary

# SQLite is the primary result store (1:many joins are intentional)
sqlite3 domain_status.db "SELECT initial_domain, http_status, title FROM url_status;"
sqlite3 domain_status.db "SELECT technology_name, COUNT(*) AS n FROM url_technologies WHERE is_implied = 0 GROUP BY 1 ORDER BY n DESC LIMIT 20;"
sqlite3 domain_status.db "SELECT secret_type, severity, COUNT(*) FROM url_exposed_secrets GROUP BY 1, 2 ORDER BY 3 DESC;"
```

Optional: `domain_status export --format csv` flattens a view for spreadsheets (lossy vs the full schema). See [QUERIES.md](QUERIES.md) and [DATABASE.md](DATABASE.md) for more SQL.

### Offline / air-gapped fingerprints

Default scans try to refresh Wappalyzer-compatible rules from GitHub (set `GITHUB_TOKEN` to raise rate limits). When remotes fail, a **bundled minimal** ruleset is used. For fully offline runs, pass a local rules path:

```bash
domain_status scan urls.txt --fingerprints /path/to/technologies
```

Caches (fingerprints, GeoIP, WHOIS, User-Agent) live under a shared root: `--cache-dir`, or `DOMAIN_STATUS_CACHE_DIR`, or the platform cache directory + `domain_status/` (Linux `~/.cache/…`, macOS `~/Library/Caches/…`). The SQLite DB and log file stay under `--db-path` / `--log-file` (cwd by default).

### Optional enrichments

| Feature | How to enable |
|---------|----------------|
| GeoIP | Set `MAXMIND_LICENSE_KEY` in `.env`, or pass `--geoip` |
| WHOIS | `--enable-whois` (disable with `--no-whois` if TOML enabled it) |
| External script scan | `--scan-external-scripts` (off by default; secrets + static tech on first-party bodies) |

## Features (core)

- HTTP status, redirects, response metadata
- TLS certificate fields (resolves all public IPs, IPv4-first, so dual-stack hosts with broken IPv6 egress still get a certificate)
- DNS (NS/TXT/MX + SPF/DMARC)
- Technology fingerprints + exposed secrets (static analysis; no JS execution). Fingerprints use headers/cookies/meta/HTML/`scriptSrc` URLs/inline script text/DNS/cert issuer from the initial response. With `--scan-external-scripts`, first-party fetched script bodies also feed secret detection and Wappalyzer `scripts` tech patterns.
- Security findings (`no_https`, `weak_tls`, `invalid_certificate`) — real observed issues only; header *presence* (HSTS/CSP/etc.) is captured separately and "missing header" is a query, not a precomputed warning (see [DATABASE.md](DATABASE.md))
- SQLite fact table + satellite tables; `summary` command
- Concurrency / rate limiting; `--fail-on` for CI exit policy

**Also available (see docs):** GeoIP, WHOIS, live status/Prometheus server, CSV/JSONL/Parquet export, TOML/`DOMAIN_STATUS_*` config. Low-signal fields such as meta keywords, viewport “mobile-friendly”, body-referenced domains, and body word/line counts are **no longer populated** on new scans (columns kept for old DBs).

## Limitations

- Static analysis only — no JavaScript rendering; JS-runtime-only fingerprint rules will not match
- Fingerprint rules depend on network refresh or a local `--fingerprints` path
- Private/link-local targets are blocked (SSRF protection)

## Configuration (keep it simple)

**Day-to-day:** CLI flags (`domain_status scan --help`). Prefer `-v` / `-q` for log verbosity.

**Repeatable jobs:** one of TOML (`--config ./domain_status.toml` or cwd `domain_status.toml`) **or** `DOMAIN_STATUS_*` env — not both as equal first-class paths. **`--config` wins** over `DOMAIN_STATUS_CONFIG_FILE`.

**Secrets stay in env:** `MAXMIND_LICENSE_KEY`, `GITHUB_TOKEN`.

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

MIT — see [LICENSE](LICENSE).
