# domain_status

[![Crates.io](https://img.shields.io/crates/v/domain_status)](https://crates.io/crates/domain_status)
[![docs.rs](https://img.shields.io/docsrs/domain_status)](https://docs.rs/domain_status)
[![Downloads](https://img.shields.io/crates/d/domain_status)](https://crates.io/crates/domain_status)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85+-orange.svg)](https://www.rust-lang.org/)
[![CI](https://github.com/alexwoolford/domain_status/actions/workflows/ci.yml/badge.svg)](https://github.com/alexwoolford/domain_status/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/alexwoolford/domain_status/branch/main/graph/badge.svg)](https://codecov.io/gh/alexwoolford/domain_status)
[![Latest Release](https://img.shields.io/github/v/release/alexwoolford/domain_status?label=latest%20release)](https://github.com/alexwoolford/domain_status/releases/latest)

**domain_status** is a fast, concurrent website scanner for bulk analysis of URLs and domains.

Give it a list of URLs → it fetches HTTP status, TLS certificates, DNS records, WHOIS data, GeoIP information, and technology fingerprints in one pass → stores everything in SQLite for analysis.

**Who it's for:**
- **DevOps/SRE teams**: Monitor uptime, certificate expiration, and site health across portfolios
- **Security analysts**: Identify outdated software, missing security headers, and configuration issues
- **Domain managers**: Track registration status, DNS configuration, and site metadata for large portfolios

**Why domain_status?** Unlike single-purpose tools (curl for status, whois for domain info, Wappalyzer for tech detection), domain_status consolidates all checks in one tool. Built with async Rust (Tokio) for high-performance concurrent processing, it efficiently handles hundreds or thousands of URLs while maintaining reliability through adaptive rate limiting and comprehensive error handling.

## Table of Contents

- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Features](#-features)
- [Use Cases](#-use-cases)
- [Limitations](#️-limitations)
- [Usage](#-usage)
- [Output & Results](#-output--results)
- [Database Schema](#-database-schema)
- [Error Handling & Exit Codes](#error-handling-and-exit-codes)
- [Monitoring](#-monitoring)
- [Advanced Topics](#-advanced-topics)
- [Troubleshooting](#-troubleshooting)
- [Library Usage](#-library-usage)
- [Technical Details](#-technical-details)
- [Architecture](#-architecture)
- [Security](#-security--secret-management)
- [Development](#-development)
- [License](#-license)

## 🚀 Quick Start (5 minutes)

**Install and run in 3 commands:**

```bash
# 1. Install via Homebrew (macOS/Linux) or Cargo (any platform)
brew tap alexwoolford/domain-status && brew install domain_status
# or: cargo install domain_status

# 2. Create URLs file and run scan
echo -e "https://example.com\nhttps://example.org" > urls.txt && domain_status scan urls.txt

# 3. View results
sqlite3 domain_status.db "SELECT initial_domain, http_status, title FROM url_status;"
```

**Optional: Enable GeoIP lookup**

If you want GeoIP data (country, city, etc.), create a `.env` file:

```bash
# Copy the example and add your MaxMind license key
cp .env.example .env
# Edit .env and add: MAXMIND_LICENSE_KEY=your_key_here
```

Get a free MaxMind license key from: https://www.maxmind.com/en/accounts/current/license-key

**Example output:**
```
initial_domain    | http_status | title
------------------|-------------|--------------------------
example.com       | 200         | Example Domain
rust-lang.org     | 200         | Rust Programming Language
```

**That's it!** The tool processes URLs concurrently (30 by default), stores all data in SQLite, and provides progress updates.

**Alternative:** Download a pre-built binary from the [Releases page](https://github.com/alexwoolford/domain_status/releases) — see [Installation](#-installation) for details.

## 📦 Installation

**Option 1: Install via Homebrew (macOS/Linux — Recommended)**

```bash
brew tap alexwoolford/domain-status
brew install domain_status
```

Pre-built binary, no compilation needed. Works on macOS (Intel and Apple Silicon) and Linux.

**Option 2: Install via Cargo (Rust users)**

Requires [Rust](https://www.rust-lang.org/tools/install) 1.85 or newer:

```bash
cargo install domain_status
```

This compiles from source and installs the binary to `~/.cargo/bin/domain_status` (or `%USERPROFILE%\.cargo\bin\domain_status.exe` on Windows). The binary is added to your PATH automatically.

**Benefits:**
- ✅ No macOS Gatekeeper warnings (compiled locally)
- ✅ Works on any platform Rust supports
- ✅ Easy updates: `cargo install --force domain_status`
- ✅ No manual downloads or extraction needed

**Note:** This crate requires Rust 1.85 or newer (for edition 2024 support in dependencies). If installation fails, update your Rust toolchain: `rustup update stable`.

**Option 3: Download Pre-built Binary**

Download the latest release from the [Releases page](https://github.com/alexwoolford/domain_status/releases):

```bash
# Linux (x86_64)
wget https://github.com/alexwoolford/domain_status/releases/latest/download/domain_status-linux-x86_64.tar.gz
tar xzf domain_status-linux-x86_64.tar.gz
chmod +x domain_status
./domain_status scan urls.txt

# macOS (Intel)
wget https://github.com/alexwoolford/domain_status/releases/latest/download/domain_status-macos-x86_64.tar.gz
tar xzf domain_status-macos-x86_64.tar.gz
chmod +x domain_status

# macOS (Apple Silicon)
wget https://github.com/alexwoolford/domain_status/releases/latest/download/domain_status-macos-aarch64.tar.gz
tar xzf domain_status-macos-aarch64.tar.gz
chmod +x domain_status

# macOS: Handle Gatekeeper warning (unsigned binary)
# Option 1: Right-click the binary, select "Open", then click "Open" in the dialog
# Option 2: Run this command to remove the quarantine attribute:
xattr -d com.apple.quarantine domain_status 2>/dev/null || true

./domain_status scan urls.txt

# Windows
# Download domain_status-windows-x86_64.exe.zip and extract
```

**Option 4: Build from Source**

Requires [Rust](https://www.rust-lang.org/tools/install) 1.85 or newer:

```bash
# Clone the repository
git clone https://github.com/alexwoolford/domain_status.git
cd domain_status

# Build release binary
cargo build --release
```

This creates an executable in `./target/release/domain_status` (or `domain_status.exe` on Windows).

**Note:** SQLite is bundled in the binary - no system SQLite installation required. The tool is completely self-contained.

## 🌟 Features

### Data Collection
- **Comprehensive URL Analysis**: Captures HTTP status, response times, HTML metadata, TLS certificates, DNS information, technology fingerprints, GeoIP location data, WHOIS registration data, structured data (JSON-LD, Open Graph, Twitter Cards), security warnings, and complete redirect chains
- **Technology Fingerprinting**: Detects web technologies using community-maintained Wappalyzer rulesets via pattern matching (headers, cookies, HTML, script URLs). Does not execute JavaScript.
- **Contact Extraction**: Extracts email addresses and phone numbers from `mailto:` and `tel:` links
- **Exposed Secret Detection**: Scans HTML for ~57 credential patterns (AWS, OpenAI, Anthropic, Stripe, Slack, GitHub, database URLs, private keys, and 40+ more). Each finding includes severity (critical/high/medium/low), location (inline_script, html_comment, url_parameter, etc.), and surrounding context for analyst triage
- **Enhanced DNS Analysis**: Queries NS, TXT, and MX records; automatically extracts SPF and DMARC policies
- **Enhanced TLS Analysis**: Captures cipher suite and key algorithm in addition to certificate details
- **Favicon Hashing**: Captures Shodan-compatible MurmurHash3 favicon hashes for infrastructure correlation
- **GeoIP Lookup**: Automatic geographic and network information lookup using MaxMind GeoLite2 databases (auto-downloads if license key provided)

### Performance
- **Concurrent Processing**: Async/await with configurable concurrency limits (default: 30 concurrent requests, 15 RPS)
- **Adaptive Rate Limiting**: Token-bucket rate limiting with automatic adjustment based on error rates (always enabled)
- **Resource Efficiency**: Shared HTTP clients, DNS resolver, and HTML parser instances across concurrent tasks

### Reliability
- **Intelligent Error Handling**: Automatic retries with exponential backoff, error rate monitoring with dynamic throttling, and comprehensive processing statistics
- **Robust Data Storage**: SQLite database with WAL mode, UPSERT semantics, and unique constraints for idempotent processing
- **Timeout Protection**: Per-URL processing timeout (35 seconds) prevents hung requests

### Integration
- **Flexible Configuration**: Extensive CLI options for logging, timeouts, concurrency, rate limits, database paths, and fingerprint rulesets
- **Library API**: Use as a Rust library in your own projects
- **Status Server**: Optional HTTP server for monitoring long-running jobs with Prometheus metrics
- **Security Features**: URL validation (http/https only), content-type filtering, response size limits, and redirect hop limits

## Error Handling and Exit Codes

domain_status provides comprehensive error handling with clear exit codes:

- **Exit Code 0**: Success or ignored failures (`--fail-on never`)
- **Exit Code 1**: Configuration or initialization error
- **Exit Code 2**: Failure threshold exceeded (policy-based)
- **Exit Code 3**: Partial success (no URLs processed)

See [docs/EXIT_CODES.md](docs/EXIT_CODES.md) for detailed exit code reference.

### Panic Safety Guarantee

The application is designed to never panic during normal operation:
- All regex patterns validated at program startup
- Division operations guarded against divide-by-zero
- Mutex operations use safe recovery strategies
- Proper error handling throughout with actionable messages

## 💼 Use Cases

**Domain Portfolio Management**: Check status of multiple domains, track redirects, verify SSL certificates, monitor domain expiration dates (with WHOIS enabled).

**Security Audits**: Identify missing security headers (CSP, HSTS, etc.), detect expired certificates, inventory technology stacks to identify potential vulnerabilities.

**Competitive Analysis**: Track technology stacks across competitors, identify analytics tools and tracking IDs, gather structured data (Open Graph, JSON-LD) for comparison.

**Monitoring**: Integrate with Prometheus for ongoing status checks via the status server endpoint, track changes over time by querying run history.

**Research**: Bulk analysis of web technologies, DNS configurations, geographic distribution of infrastructure, technology adoption patterns.

Unlike single-purpose tools (curl, nmap, whois), domain_status consolidates many checks in one sweep, ensuring consistency and saving time.

## ⚠️ Limitations

**What This Tool Does NOT Do:**

- **No JavaScript Execution**: Analyzes initial HTML response only (like WappalyzerGo). Does not execute JavaScript, render pages, or interact with dynamic content. This means:
  - Single-page apps (SPAs) that load content via JS may appear empty
  - Client-side rendered technologies may not be detected
  - JavaScript-based redirects are not followed

- **Rate Limiting**: Processing speed is constrained by:
  - Target server response times and rate limits
  - Adaptive rate limiter (backs off on errors)
  - WHOIS lookups add ~1 second per domain
  - Typical throughput: 0.5-2 URLs/sec with default settings

- **Not a Full Browser**: This is a CLI scanner, not a browser automation tool. It:
  - Cannot click buttons or fill forms
  - Cannot capture screenshots
  - Cannot handle authentication flows
  - Works best for public, server-rendered content

**Best For**: Public websites with server-rendered HTML, bulk analysis, infrastructure monitoring, competitive research.

**Not Ideal For**: SPAs requiring JavaScript, authenticated sites, sites with heavy client-side rendering.

## 📖 Usage

### Command Structure

The tool uses a subcommand-based interface:

- **`domain_status scan <file>`** - Scan URLs and store results in SQLite database
  - Use `-` as filename to read URLs from stdin: `echo "https://example.com" | domain_status scan -`
- **`domain_status export`** - Export data from SQLite database to various formats (CSV, JSONL, Parquet)

### Scan Command

**Usage:**
```bash
domain_status scan <file> [OPTIONS]
```

**Common Options:**
- `--log-level <LEVEL>`: Log level: `error`, `warn`, `info`, `debug`, or `trace` (default: `info`)
- `--log-file <PATH>`: Log file path (default: `domain_status.log`). All logs are written to this file with timestamps.
- `--db-path <PATH>`: SQLite database file path (default: `./domain_status.db`)
- `--max-concurrency <N>`: Maximum concurrent requests (default: 30)
- `--timeout-seconds <N>`: HTTP client timeout in seconds (default: 10). Note: Per-URL processing timeout is 35 seconds.
- `--rate-limit-rps <N>`: Initial requests per second (adaptive rate limiting always enabled, default: 15)
- `--status-port <PORT>`: Start HTTP status server on the specified port (optional, disabled by default)
- `--fail-on <POLICY>`: Exit code policy for CI integration: `never` (default), `any-failure`, or `pct>X`. See [Exit Code Control](#exit-code-control) for details.

**Advanced Options:**
- `--user-agent <STRING>`: HTTP User-Agent header value (default: Chrome user agent)
- `--fingerprints <URL|PATH>`: Technology fingerprint ruleset source (URL or local path). Default: HTTP Archive Wappalyzer fork. Rules are cached locally for 7 days.
- `--geoip <PATH|URL>`: GeoIP database path (MaxMind GeoLite2 .mmdb file) or download URL. If not provided, will auto-download if `MAXMIND_LICENSE_KEY` environment variable is set.
- `--enable-whois`: Enable WHOIS/RDAP lookup for domain registration information. WHOIS data is cached for 7 days. Default: disabled.

**Example:**
```bash
domain_status scan urls.txt \
  --db-path ./results.db \
  --max-concurrency 100 \
  --timeout-seconds 15 \
  --log-level debug \
  --rate-limit-rps 20 \
  --status-port 8080
```

**Exit Code Control (`--fail-on`):**

The `--fail-on` option controls when the scan command exits with a non-zero code, making it ideal for CI/CD pipelines:

- `never` (default): Always return exit code 0, even if some URLs failed. Useful for monitoring scenarios where you want to log failures but not trigger alerts.
- `any-failure`: Exit with code 2 if any URL failed. Strict mode for CI pipelines where any failure should be treated as a build failure.
- `pct>X`: Exit with code 2 if failure percentage exceeds X (e.g., `pct>10` means exit if more than 10% failed). Use with `--fail-on-pct-threshold` to set the exact percentage. Useful for large scans where some failures are expected.

**Exit Codes:**
- `0`: Success (or failures ignored by policy)
- `1`: Configuration error or scan initialization failure
- `2`: Failures exceeded threshold (based on `--fail-on` policy)
- `3`: Partial success (some URLs processed, but scan incomplete)

**Examples:**
```bash
# CI mode: fail if any URL fails
domain_status scan urls.txt --fail-on any-failure

# Allow up to 10% failures before failing
domain_status scan urls.txt --fail-on pct>10 --fail-on-pct-threshold 10

# Monitoring mode: always succeed (default)
domain_status scan urls.txt --fail-on never
```

### Export Command

**Usage:**
```bash
domain_status export [OPTIONS]
```

**Options:**
- `--db-path <PATH>`: SQLite database file path (default: `./domain_status.db`)
- `--format <FORMAT>`: Export format: `csv`, `jsonl`, or `parquet` (default: `csv`)
  - **CSV**: Flattened format, one row per URL with all fields as columns (ideal for spreadsheets)
  - **JSONL**: JSON Lines format, one JSON object per line (ideal for scripting, piping to `jq`, or loading into databases)
  - **Parquet**: Columnar format for analytics (Arrow-typed columns)
- `--output <PATH>`: Output file path
  - If not specified, writes to `domain_status_export.{csv,jsonl,parquet}` in the current directory
  - Use `-` to write to stdout (for piping to other commands)
- `--run-id <ID>`: Filter by run ID
- `--domain <DOMAIN>`: Filter by domain (matches initial or final domain)
- `--status <CODE>`: Filter by HTTP status code
- `--since <TIMESTAMP>`: Filter by timestamp (milliseconds since epoch)

**Examples:**
```bash
# Export all data to CSV (defaults to domain_status_export.csv)
domain_status export --format csv

# Export to a custom file
domain_status export --format csv --output results.csv

# Export to stdout (pipe to another command)
domain_status export --format jsonl --output - 2>/dev/null | jq '.final_domain'

# Export only successful URLs (status 200)
domain_status export --format csv --status 200 --output successful.csv

# Pipe JSONL to jq for filtering (log messages go to stderr automatically)
domain_status export --format jsonl --output - 2>/dev/null | jq 'select(.status == 200) | .final_domain'

# Export and filter with jq (e.g., get domains with specific technologies)
domain_status export --format jsonl --output - 2>/dev/null | jq 'select(.technologies[].name == "WordPress") | .final_domain'
```

### Environment Variables

Environment variables can be set in a `.env` file (in the current directory or next to the executable) or exported in your shell.

**Configuration Precedence** (highest to lowest):
1. **Command-line arguments** - always take precedence
2. **Environment variables** (for specific features like GeoIP, GitHub API) - used when CLI args not provided
3. **Default values** - fallback when neither CLI args nor env vars are set

Most configuration is done via CLI arguments. Environment variables are used only for API keys and advanced logging.

**Available Environment Variables:**

- `MAXMIND_LICENSE_KEY`: MaxMind license key for automatic GeoIP database downloads. Get a free key from [MaxMind](https://www.maxmind.com/en/accounts/current/license-key). If not set, GeoIP lookup is disabled and the application continues normally.
- `GITHUB_TOKEN`: (Optional) GitHub personal access token for fingerprint ruleset downloads. Increases GitHub API rate limit from 60 to 5000 requests/hour. Only needed if using GitHub-hosted fingerprint rulesets.
- `RUST_LOG`: (Optional) Advanced logging control. Overrides `--log-level` CLI argument if set. Format: `domain_status=debug,reqwest=info`. See [env_logger documentation](https://docs.rs/env_logger/) for details.

**Sensitive environment variables:** `MAXMIND_LICENSE_KEY` and `GITHUB_TOKEN` are secrets. Never commit them to version control or log their values. Use a `.env` file (already in `.gitignore`) or your shell environment, and use CI secrets for automation.

**Example `.env` file:**
```bash
# Copy .env.example to .env and customize
MAXMIND_LICENSE_KEY=your_license_key_here
GITHUB_TOKEN=your_github_token_here
```

**Other Configuration:**

- Database path: Use `--db-path` CLI argument (default: `./domain_status.db`)
- All scanning options: Use CLI arguments (run `domain_status scan --help` for full list)

### URL Input

**Input File:**
- URLs can be provided with or without `http://` or `https://` prefix
- If no scheme is provided, `https://` is automatically prepended
- Only `http://` and `https://` URLs are accepted; other schemes are rejected
- Invalid URLs are skipped with a warning
- **Empty lines and comments are automatically skipped**: Lines starting with `#` are treated as comments and ignored
- **STDIN support**: Use `-` as the filename to read URLs from stdin:
  ```bash
  echo -e "https://example.com\nhttps://example.org" | domain_status scan -
  cat urls.txt | domain_status scan -
  ```

**Example input file:**
```bash
# My domain list
# Production domains
https://example.com
https://www.example.com

# Staging domains
https://staging.example.com
```

## 📊 Output & Results

After a scan completes, all data is stored in the SQLite database. Use `domain_status export` to export data in CSV/JSON format, or query the database directly.

### Duplicate Domain Handling

The database uses a `UNIQUE (final_domain, observed_at_ms)` constraint to ensure idempotency. This means:

- **Same domain, same run**: If you include the same domain multiple times in one input file, only one record will be stored (the last one processed). This is by design to avoid duplicate data.
- **Same domain, different runs**: Each run creates a new record with a different observation time, so you can track changes over time.
- **Different paths on same domain**: If you include both `https://example.com/` and `https://example.com/page`, both will be processed, but they will resolve to the same `final_domain` after following redirects. The database stores the final domain after redirects, so only one record per final domain per observation is kept.

**Best practice:** Include each domain only once per input file. If you need to check multiple paths on the same domain, they should be separate URLs (e.g., `https://example.com/` and `https://example.com/about`), but be aware that redirects may cause them to resolve to the same final domain.

### Progress Display

The tool shows a clean progress bar during scanning, with detailed logs written to a file:

```
📝 Logs: domain_status.log
⠋ [00:00:45] [████████████████████░░░░░░░░░░░░░░░░░░░░] 52/100 (52%) ✓48 ✗4
```

After completion:
```
✅ Processed 100 URLs (92 succeeded, 8 failed) in 55.9s - see database for details
Results saved in ./domain_status.db
💡 Tip: Use `domain_status export --format csv` to export data, or query the database directly.
```

**Log file format** (with timestamps):
```
[2025-01-07 23:33:59.123] INFO domain_status::run - Total URLs in file: 100
[2025-01-07 23:33:59.456] INFO domain_status::fingerprint::ruleset - Merged 7223 technologies from 2 source(s)
[2025-01-07 23:34:01.789] WARN domain_status::dns::resolution - Failed to perform reverse DNS lookup...
```

**Performance Analysis:**

Detailed timing metrics are automatically logged to the log file (`domain_status.log` by default) at the end of each scan. This includes a breakdown of time spent in each operation:

Example log output:
```
=== Timing Metrics Summary (88 URLs) ===
Average times per URL:
  HTTP Request:          1287 ms (40.9%)
  DNS Forward:            845 ms (26.8%)
  TLS Handshake:         1035 ms (32.9%)
  HTML Parsing:            36 ms (1.1%)
  Tech Detection:        1788 ms (56.8%)
  Total:                 3148 ms
```

**Note:** Performance varies significantly based on rate limiting, network conditions, target server behavior, and error handling. Expect 0.5-2 lines/sec with default settings. Higher rates may trigger bot detection.

### Querying Results

All results are stored in the SQLite database. You can query the database while the scan is running (WAL mode allows concurrent reads). Here are some useful queries:

**Basic status overview:**
```sql
SELECT initial_domain, http_status, http_status_text, response_time_seconds
FROM url_status
ORDER BY initial_domain;
```

**Find all failed URLs:**
```sql
SELECT initial_domain, error_type, error_message
FROM url_failures
ORDER BY error_type;
```

**Find all sites using a specific technology:**
```sql
SELECT DISTINCT us.initial_domain, us.http_status
FROM url_status us
JOIN url_technologies ut ON us.id = ut.url_status_id
WHERE ut.technology_name = 'WordPress'
ORDER BY us.initial_domain;
```

**Find sites with missing security headers:**
```sql
SELECT DISTINCT us.initial_domain
FROM url_status us
JOIN url_security_warnings usw ON us.id = usw.url_status_id
WHERE usw.warning_code LIKE '%missing%'
ORDER BY us.initial_domain;
```

**Find exposed secrets (sorted by severity):**
```sql
SELECT us.initial_domain, es.secret_type, es.severity, es.location, es.matched_value
FROM url_exposed_secrets es
JOIN url_status us ON es.url_status_id = us.id
ORDER BY CASE es.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 END;
```

**Find all redirects:**
```sql
SELECT
    us.initial_domain,
    us.final_domain,
    us.http_status,
    COUNT(urc.id) as redirect_count
FROM url_status us
JOIN url_redirect_chain urc ON us.id = urc.url_status_id
GROUP BY us.id
HAVING redirect_count > 0
ORDER BY redirect_count DESC;
```

**Compare runs by version:**
```sql
SELECT version, COUNT(*) as runs,
       SUM(total_urls) as total_urls,
       AVG(elapsed_seconds) as avg_time
FROM runs
WHERE end_time_ms IS NOT NULL
GROUP BY version
ORDER BY version DESC;
```

**Get all URLs from a specific run:**
```sql
SELECT initial_domain, http_status, title, response_time_seconds
FROM url_status
WHERE run_id = 'run_1765150444953'
ORDER BY initial_domain;
```

## 📊 Database Schema

The database uses a **star schema** design pattern with:
- **Fact Table**: `url_status` (main URL data)
- **Dimension Table**: `runs` (run-level metadata including version)
- **Junction Tables**: Multi-valued fields (technologies, headers, DNS records, etc.)
- **One-to-One Tables**: `url_geoip`, `url_whois`
- **Failure Tracking**: `url_failures` with related tables for error context (redirect chains, request/response headers)

**Key Features:**
- WAL mode for concurrent reads/writes
- **Idempotency:** `UNIQUE (final_domain, observed_at_ms)` ensures at most one row per final domain per observation time. A new run with the same URL can overwrite that row if it falls in the same millisecond window; runs in the same second can overwrite each other. For repeat scans, include each URL once per run and use run_id to distinguish runs.
- Comprehensive indexes for fast queries
- Normalized structure for efficient storage and analytics

For complete database schema documentation including entity-relationship diagrams, table descriptions, indexes, constraints, and query examples, see [DATABASE.md](DATABASE.md).

### Database Capabilities Highlights

Beyond basic URL status checks, the database enables powerful analytical capabilities:

#### 🔗 Graph Analysis
- **Certificate Ownership Mapping**: Find domains sharing SSL certificates via `url_certificate_sans` table - indicates common ownership or infrastructure
- **Analytics-Based Linking**: Connect domains using the same Google Analytics, Facebook Pixel, or GTM IDs via `url_analytics_ids` - reveals common management
- **Infrastructure Relationships**: Discover domains on shared hosting, CDNs, or managed by the same team

**Example**: Find all domains sharing a certificate with example.com:
```sql
SELECT DISTINCT us2.final_domain
FROM url_certificate_sans san1
JOIN url_certificate_sans san2 ON san1.san_value = san2.san_value
JOIN url_status us1 ON san1.url_status_id = us1.id
JOIN url_status us2 ON san2.url_status_id = us2.id
WHERE us1.final_domain = 'example.com' AND us1.id != us2.id;
```

#### 📊 Cross-Table Analysis
- **Contact Intelligence**: Extract email addresses and phone numbers across all scanned domains via `url_contact_links`
- **Secret Detection**: Find exposed credentials with severity classification via `url_exposed_secrets`
- **Infrastructure Mapping**: Group domains by shared IP, certificate, or ASN

#### 📈 Time-Series Tracking
- Compare technology stacks between runs (track migrations: WordPress → React)
- Monitor infrastructure changes (new CDNs, certificate updates, DNS changes)
- Track domain status over time (identify reliability patterns)

**Example**: Compare technologies between two runs:
```sql
SELECT ut1.technology_name,
       COUNT(DISTINCT us1.id) as run1_count,
       COUNT(DISTINCT us2.id) as run2_count
FROM url_status us1
JOIN url_technologies ut1 ON us1.id = ut1.url_status_id
LEFT JOIN url_status us2 ON us1.final_domain = us2.final_domain AND us2.run_id = 'run_456'
LEFT JOIN url_technologies ut2 ON us2.id = ut2.url_status_id AND ut1.technology_name = ut2.technology_name
WHERE us1.run_id = 'run_123'
GROUP BY ut1.technology_name;
```

For more examples and detailed schema documentation, see [DATABASE.md](DATABASE.md).

### Querying Run History

All scan results are persisted in the database, so you can query past runs even after closing the terminal. The `runs` table stores summary statistics for each scan:

```sql
-- View all completed runs (most recent first)
SELECT
    run_id,
    version,
    datetime(start_time_ms/1000, 'unixepoch') as start_time,
    datetime(end_time_ms/1000, 'unixepoch') as end_time,
    elapsed_seconds,
    total_urls,
    successful_urls,
    failed_urls,
    ROUND(100.0 * successful_urls / total_urls, 1) as success_rate
FROM runs
WHERE end_time_ms IS NOT NULL
ORDER BY start_time_ms DESC
LIMIT 10;
```

**Example output:**
```
run_id              | version | start_time          | end_time            | elapsed_seconds | total_urls | successful_urls | failed_urls | success_rate
--------------------|---------|---------------------|---------------------|-----------------|------------|-----------------|------------|--------------
run_1765150444953   | 0.1.4   | 2025-01-07 23:33:59 | 2025-01-07 23:34:52 | 52.1            | 100        | 89              | 11         | 89.0
```

**Using the library API:**

```rust
use domain_status::storage::query_run_history;
use sqlx::SqlitePool;

let pool = SqlitePool::connect("sqlite:./domain_status.db").await?;
let runs = query_run_history(&pool, Some(10)).await?;

for run in runs {
    println!("Run {}: {} URLs ({} succeeded, {} failed) in {:.1}s",
             run.run_id, run.total_urls, run.successful_urls,
             run.failed_urls, run.elapsed_seconds.unwrap_or(0.0));
}
```

## 📈 Monitoring

For long-running jobs, you can monitor progress via an optional HTTP status server. **The status server has no authentication.** Bind only to localhost (e.g. use `127.0.0.1:8080` when scraping); do not expose it to the network or protect it behind auth if you do.

```bash
# Start with status server on port 8080
domain_status scan urls.txt --status-port 8080
```

# In another terminal, check progress:
curl http://127.0.0.1:8080/status | jq

# Or view Prometheus metrics:
curl http://127.0.0.1:8080/metrics
```

The status server provides:
- **Real-time progress**: Total URLs, completed, failed, percentage complete, processing rate
- **Error breakdown**: Detailed counts by error type
- **Warning/info metrics**: Track missing metadata, redirects, bot detection events
- **Prometheus compatibility**: Metrics endpoint ready for Prometheus scraping

### Status Endpoint (`/status`)

Returns detailed JSON status with real-time progress information:

```bash
curl http://127.0.0.1:8080/status | jq
```

**Response Format:**
```json
{
  "total_urls": 100,
  "completed_urls": 85,
  "failed_urls": 2,
  "pending_urls": 13,
  "percentage_complete": 87.0,
  "elapsed_seconds": 55.88,
  "rate_per_second": 1.52,
  "errors": { "total": 17, "timeout": 0, "connection_error": 0, "http_error": 3, "dns_error": 14, "tls_error": 0, "parse_error": 0, "other_error": 0 },
  "warnings": { "total": 104, "missing_meta_keywords": 77, "missing_meta_description": 25, "missing_title": 2 },
  "info": { "total": 64, "http_redirect": 55, "https_redirect": 0, "bot_detection_403": 3, "multiple_redirects": 6 }
}
```

### Metrics Endpoint (`/metrics`)

Returns Prometheus-compatible metrics in text format:

```bash
curl http://127.0.0.1:8080/metrics
```

**Metrics:**
- `domain_status_total_urls` (gauge): Total URLs to process
- `domain_status_completed_urls` (gauge): Successfully processed URLs
- `domain_status_failed_urls` (gauge): Failed URLs
- `domain_status_percentage_complete` (gauge): Completion percentage (0-100)
- `domain_status_rate_per_second` (gauge): Processing rate (URLs/sec)
- `domain_status_errors_total` (counter): Total error count
- `domain_status_warnings_total` (counter): Total warning count
- `domain_status_info_total` (counter): Total info event count

**Prometheus Integration:**
```yaml
scrape_configs:
  - job_name: 'domain_status'
    static_configs:
      - targets: ['localhost:8080']
```

## 🔧 Advanced Topics

### GeoIP Setup

To enable GeoIP, set the `MAXMIND_LICENSE_KEY` environment variable and the tool will automatically download the MaxMind GeoLite2 databases on first run:

```bash
export MAXMIND_LICENSE_KEY=your_license_key_here
domain_status scan urls.txt
```

The databases are cached in `.geoip_cache/` and reused for subsequent runs. Alternatively, download the `.mmdb` files yourself and use `--geoip` to point to them. GeoIP data is stored in the `url_geoip` table with fields for country, region, city, coordinates, and ASN.

If GeoIP fails or no key is provided, the tool safely skips GeoIP lookup with a warning and continues normally.

### WHOIS/RDAP Details

The `--enable-whois` flag performs WHOIS/RDAP queries to fetch domain registration information. This significantly slows down processing (adds approximately 1 second per domain) due to rate limits imposed by registrars.

**Rate Limiting**: WHOIS queries are rate-limited to 0.5 queries/second (1 query per 2 seconds) to respect registrar limits. This is separate from HTTP rate limiting.

**Caching**: WHOIS data is cached in `.whois_cache/` by domain name for 7 days to avoid redundant queries.

**Limitations**: Not all TLDs provide public WHOIS via port 43, and some registrars limit the data returned. RDAP fallback helps but is not universal. If a WHOIS server blocks you, you may see warnings in the logs.

Enable this flag only when you need registrar/expiration information. For faster scans, leave it disabled (default).

### Technology Fingerprinting

Technology detection uses pattern matching against:
- HTTP headers (Server, X-Powered-By, etc.)
- Cookies
- Meta tags (name, property, http-equiv)
- Script source URLs (from HTML, not fetched)
- HTML text content
- URL patterns
- Script tag IDs (e.g., `__NEXT_DATA__` for Next.js)

**Important**: The tool does NOT execute JavaScript or fetch external scripts. It only analyzes the initial HTML response, matching WappalyzerGo's behavior.

The default fingerprint ruleset comes from the HTTP Archive Wappalyzer fork and is cached locally for 7 days. You can update to the latest by pointing `--fingerprints` to a new JSON file (e.g., the official Wappalyzer `technologies.json`). The tool prints the fingerprints source and version (commit hash) in the `runs` table.

If you maintain your own fingerprint file (e.g., for internal technologies), you can use that too.

### Performance Tuning

**Concurrency**: The default is 30 concurrent requests. If you have good bandwidth and target sites can handle it, you can increase `--max-concurrency`. Monitor the `/metrics` endpoint's rate to see actual throughput. Conversely, if you encounter many timeouts or want to be gentle on servers, lower concurrency.

**Rate Limiting**: The default is 15 RPS with adaptive adjustment. The adaptive rate limiter:
- Starts at initial RPS (default: 15)
- Monitors 429 errors and timeouts in a sliding window
- Automatically reduces RPS by 50% when error rate exceeds threshold (default: 20%)
- Gradually increases RPS by 15% when error rate is below threshold
- Maximum RPS capped at 2x initial value

**Memory**: Each concurrent task consumes memory for HTML and data. With default settings, memory usage is moderate. If scanning extremely large pages, consider that response bodies are capped at 2MB and HTML text extraction is limited to 50KB.

### Error Handling & Retries

The tool automatically retries failed HTTP requests up to 2 additional times (3 total attempts) with exponential backoff (initial: 500ms, max: 15s). If a domain consistently fails (e.g., DNS not resolved, or all attempts timed out), it will be marked in the `url_failures` table with details. The errors section of the status output counts these. You don't need to re-run for transient errors; they are retried on the fly.

## ❓ Troubleshooting

**Scan is very slow or stuck:**
- Check if you hit a rate limit. domain_status automatically slows down on high error rate (adaptive rate limiting).
- Enabling WHOIS adds approximately 1 second per domain due to rate limits.
- If it's truly stuck, check the log file (`domain_status.log` by default) or use `--log-level debug` for more detail.

**I see 'bot_detection_403' in info metrics:**
- Some sites actively block non-browser agents. Try using `--user-agent` to mimic a different browser or reduce rate with `--rate-limit-rps`.

**Database is locked error:**
- If you open the DB in another tool while scanning, thanks to WAL mode reads should be fine.
- However, writing from two domain_status processes to the same DB is not supported (each run uses its own DB by default).

**WHOIS data seems incomplete for some TLDs:**
- Not all registrars provide the same info; domain_status tries its best.
- Some ccTLDs don't have public WHOIS via port 43.
- RDAP fallback helps but is not universal.

**GeoIP shows "unknown" or is empty:**
- Probably the MaxMind license key wasn't set or the download failed.
- Ensure internet access for the first run or provide the `.mmdb` files manually with `--geoip`.
- Check that the license key is valid and has GeoLite2 access enabled.

**Compilation fails (for users building from source):**
- Make sure Rust is updated to latest stable (1.85 or newer required).
- If error relates to a crate, run `cargo update`.
- On Windows, ensure OpenSSL or Schannel is available if reqwest needs it (rare, as we use rustls by default).

**Technology detection seems wrong:**
- Pattern matching can have false positives. Wappalyzer rules are community-maintained.
- If you get an obvious false positive, you can verify by visiting the site manually.
- You can update or customize the fingerprints to tweak this (see Technology Fingerprinting above).

**How do I update the tool?**
- If using `cargo install`, run `cargo install --force domain_status` to get the latest version.
- Check the CHANGELOG for any breaking changes in flags or output.

## 📚 Library Usage

You can also use `domain_status` as a Rust library in your own projects. Add it to your `Cargo.toml`:

```toml
[dependencies]
domain_status = "^0.1"
tokio = { version = "1", features = ["full"] }
```

Then use it in your code:

```rust
use domain_status::export::{export_csv, ExportFormat, ExportOptions};
use domain_status::{Config, run_scan};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config {
        file: PathBuf::from("urls.txt"),
        max_concurrency: 50,
        rate_limit_rps: 20,
        enable_whois: false,
        ..Default::default()
    };

    let report = run_scan(config).await?;
    println!("Processed {} URLs: {} succeeded, {} failed",
             report.total_urls, report.successful, report.failed);
    println!("Results saved in {}", report.db_path.display());

    // Export to CSV using the library API
    let export_opts = ExportOptions {
        db_path: report.db_path.clone(),
        output: Some(PathBuf::from("results.csv")),
        format: ExportFormat::Csv,
        run_id: None,
        domain: None,
        status: None,
        since: None,
    };
    export_csv(&export_opts).await?;
    println!("Exported results to results.csv");

    Ok(())
}
```

See the [API documentation](https://docs.rs/domain_status) for details on `Config` options and usage.

**Note:** The library requires a Tokio runtime. Use `#[tokio::main]` in your application or ensure you're calling library functions within an async context. When using the library, `log_file` can be `None`; the CLI requires it for file-based logging.

## 🛠️ Technical Details

**Dependencies:**
- **HTTP Client**: `reqwest` with `rustls` TLS backend
- **DNS Resolution**: `hickory-resolver` (async DNS with system config fallback)
- **Domain Extraction**: `psl` crate for accurate domain parsing (handles multi-part TLDs correctly)
- **HTML Parsing**: `scraper` (CSS selector-based extraction)
- **TLS/Certificates**: `tokio-rustls` and `x509-parser` for certificate analysis
- **Technology Detection**: Custom implementation using Wappalyzer rulesets with pattern matching (headers, cookies, HTML, script URLs). Does not execute JavaScript.
- **WHOIS/RDAP**: `whois-service` crate for domain registration lookups
- **GeoIP**: `maxminddb` for geographic and network information
- **Database**: `sqlx` with SQLite (WAL mode enabled)
- **Async Runtime**: Tokio

**Security:**
- **Security Audit**: `cargo-audit` runs in CI to detect known vulnerabilities in dependencies (uses RustSec advisory database)
- **Secret Scanning**: `gitleaks` scans commits and code for accidentally committed secrets, API keys, tokens, and credentials
- **Code Quality**: Clippy with `-D warnings` enforces strict linting rules and catches security issues

## 🏗️ Architecture

**domain_status** follows a pipeline architecture:

```
Input File → URL Validation → Concurrent Processing → Data Extraction → Direct Database Writes → SQLite Database
```

**Core Components:**
1. **Main Orchestrator**: Reads URLs, validates, normalizes, manages concurrency
2. **HTTP Request Handler**: Fetches URLs, follows redirects, extracts response data
3. **Data Extraction**: Parses HTML, detects technologies, queries DNS/TLS/GeoIP/WHOIS (parallelized where possible)
4. **Database Writer**: Direct writes to SQLite (WAL mode handles concurrency efficiently)
5. **Error Handling**: Categorizes errors, implements retries with exponential backoff
6. **Rate Limiting**: Token-bucket algorithm with adaptive adjustment

**Concurrency Model:**
- Async runtime: Tokio
- Concurrency control: Semaphore limits concurrent tasks
- Rate limiting: Token-bucket with adaptive adjustment
- Background tasks: Status server (optional), adaptive rate limiter
- Graceful shutdown: All background tasks cancellable via `CancellationToken`
- Parallel execution: Technology detection and DNS/TLS fetching run in parallel (independent operations)

**Performance Characteristics:**
- Non-blocking I/O for all network operations
- Shared resources (HTTP client, DNS resolver, database pool) across tasks
- Bounded concurrency prevents resource exhaustion
- Direct database writes with SQLite WAL mode (efficient concurrent writes)
- Memory efficiency: Response bodies limited to 2MB, HTML text extraction limited to 50KB

## 🔒 Security & Secret Management

**Preventing Credential Leaks:**

1. **Pre-commit hooks** (recommended): Install pre-commit hooks to catch secrets before they're committed:
   ```bash
   # Install pre-commit (if not already installed)
   brew install pre-commit  # macOS
   # or: pip install pre-commit

   # Install hooks
   pre-commit install
   ```
   This will automatically scan for secrets before every commit.

2. **CI scanning**: Gitleaks runs in CI to catch secrets in pull requests and scan git history.

3. **GitHub Secret Scanning**: GitHub automatically scans public repositories for known secret patterns (enabled by default).

4. **Best practices**:
   - Never commit `.env` files (already in `.gitignore`)
   - Use environment variables for all secrets
   - Use GitHub Secrets for CI/CD tokens
   - Review gitleaks output if CI fails

## 🔨 Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines and conventions.

See [TESTING.md](TESTING.md) for detailed information about:
- Test structure (unit, integration, e2e)
- Running tests locally
- Code quality checks (fmt, clippy, audit)
- CI test coverage

### Quick Start

```bash
# Run all checks
just check

# Full CI pipeline
just ci

# Install pre-commit hooks
just install-hooks
```

### Developer Tools

We use `just` for task automation: `cargo install just`

Common commands:
- `just check` - Format + lint + test
- `just ci` - Full CI pipeline
- `just lint` - Run clippy
- `just test` - Run tests
- `just coverage` - Generate coverage

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## License

MIT License - see [LICENSE](LICENSE) file for details.
