# domain_status

[![CI](https://github.com/alexwoolford/domain_status/actions/workflows/ci.yml/badge.svg)](https://github.com/alexwoolford/domain_status/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/alexwoolford/domain_status/branch/main/graph/badge.svg)](https://codecov.io/gh/alexwoolford/domain_status)
[![Latest Release](https://img.shields.io/github/v/release/alexwoolford/domain_status?label=latest%20release)](https://github.com/alexwoolford/domain_status/releases/latest)

**domain_status** is a Rust-based tool designed for high-performance concurrent checking of URL statuses and redirections. Built with async/await (Tokio), it processes URLs efficiently while capturing comprehensive metadata including TLS certificates, HTML content, DNS information, technology fingerprints, and redirect chains.

## Table of Contents

- [Quick Start](#-quick-start)
- [Features](#-features)
- [Usage](#-usage)
- [Configuration](#-configuration)
- [Data Captured](#-data-captured)
- [Database Schema](#-database-schema)
- [Output](#-output)
- [Performance](#-performance--scalability)
- [Technical Details](#-technical-details)
- [Architecture](#-architecture)
- [Development](#-development)
- [License](#-license)

## 🚀 Quick Start

### Installation

**Option 1: Download Pre-built Binary (Recommended)**

Download the latest release from the [Releases page](https://github.com/alexwoolford/domain_status/releases):

```bash
# Linux (x86_64)
wget https://github.com/alexwoolford/domain_status/releases/latest/download/domain_status-linux-x86_64.tar.gz
tar xzf domain_status-linux-x86_64.tar.gz
chmod +x domain_status
./domain_status urls.txt

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

./domain_status urls.txt

# Windows
# Download domain_status-windows-x86_64.exe.zip and extract
```

**Option 2: Build from Source**

Requires [Rust](https://www.rust-lang.org/tools/install) (stable toolchain):

```bash
# Clone the repository
git clone https://github.com/alexwoolford/domain_status.git
cd domain_status

# Build release binary
cargo build --release
```

This creates an executable in `./target/release/domain_status` (or `domain_status.exe` on Windows).

**Option 3: Install via Cargo (Future)**

Once published to crates.io:
```bash
cargo install domain_status
```

### Basic Usage

```bash
domain_status urls.txt
```

The tool will:
- Process URLs from the input file
- Store results in `./url_checker.db` (SQLite)
- Display progress and statistics
- Handle errors gracefully with automatic retries

## 🌟 Features

* **High-Performance Concurrency**: Async/await with configurable concurrency limits (default: 30 concurrent requests, 15 RPS)
* **Comprehensive URL Analysis**: Captures HTTP status, response times, HTML metadata, TLS certificates, DNS information, technology fingerprints, GeoIP location data, WHOIS registration data, structured data (JSON-LD, Open Graph, Twitter Cards), security warnings, and complete redirect chains
* **Technology Fingerprinting**: Detects web technologies using community-maintained Wappalyzer rulesets with JavaScript execution for dynamic detection
* **GeoIP Lookup**: Automatic geographic and network information lookup using MaxMind GeoLite2 databases (auto-downloads if license key provided)
* **Enhanced DNS Analysis**: Queries NS, TXT, and MX records; automatically extracts SPF and DMARC policies
* **Enhanced TLS Analysis**: Captures cipher suite and key algorithm in addition to certificate details
* **Intelligent Error Handling**: Automatic retries with exponential backoff, error rate monitoring with dynamic throttling, and comprehensive processing statistics
* **Rate Limiting**: Token-bucket rate limiting with adaptive adjustment based on error rates
* **Robust Data Storage**: SQLite database with WAL mode, UPSERT semantics, and unique constraints for idempotent processing
* **Flexible Configuration**: Extensive CLI options for logging, timeouts, concurrency, rate limits, database paths, and fingerprint rulesets
* **Security Features**: URL validation (http/https only), content-type filtering, response size limits, and redirect hop limits

## 📖 Usage

### Command-Line Options

**Common Options:**
- `--log-level <LEVEL>`: Log level: `error`, `warn`, `info`, `debug`, or `trace` (default: `info`)
- `--log-format <FORMAT>`: Log format: `plain` or `json` (default: `plain`)
- `--db-path <PATH>`: SQLite database file path (default: `./url_checker.db`)
- `--max-concurrency <N>`: Maximum concurrent requests (default: 30)
- `--timeout-seconds <N>`: HTTP client timeout in seconds (default: 10). Note: Per-URL processing timeout is 35 seconds.
- `--rate-limit-rps <N>`: Initial requests per second (adaptive rate limiting always enabled, default: 15)
- `--show-timing`: Display detailed timing metrics at the end of the run (default: disabled)
- `--status-port <PORT>`: Start HTTP status server on the specified port (optional, disabled by default)

**Advanced Options:**
- `--user-agent <STRING>`: HTTP User-Agent header value (default: Chrome user agent)
- `--fingerprints <URL|PATH>`: Technology fingerprint ruleset source (URL or local path). Default: HTTP Archive Wappalyzer fork. Rules are cached locally for 7 days.
- `--geoip <PATH|URL>`: GeoIP database path (MaxMind GeoLite2 .mmdb file) or download URL. If not provided, will auto-download if `MAXMIND_LICENSE_KEY` environment variable is set.
- `--enable-whois`: Enable WHOIS/RDAP lookup for domain registration information. WHOIS data is cached for 7 days. Default: disabled.

**Example:**
```bash
domain_status urls.txt \
  --db-path ./results.db \
  --max-concurrency 100 \
  --timeout-seconds 15 \
  --log-level debug \
  --log-format json \
  --rate-limit-rps 20 \
  --show-timing \
  --status-port 8080
```

### Monitoring Long-Running Jobs

For long-running jobs, you can monitor progress via an optional HTTP status server:

```bash
# Start with status server on port 8080
domain_status urls.txt --status-port 8080

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

See [Status Endpoint](#status-endpoint-status) and [Metrics Endpoint](#metrics-endpoint-metrics) sections below for detailed API documentation.

### Environment Variables

- `MAXMIND_LICENSE_KEY`: MaxMind license key for automatic GeoIP database downloads. Get a free key from [MaxMind](https://www.maxmind.com/en/accounts/current/license-key). If not set, GeoIP lookup is disabled and the application continues normally.
- `URL_CHECKER_DB_PATH`: Override default database path (alternative to `--db-path`)

### URL Input

- URLs can be provided with or without `http://` or `https://` prefix
- If no scheme is provided, `https://` is automatically prepended
- Only `http://` and `https://` URLs are accepted; other schemes are rejected
- Invalid URLs are skipped with a warning

## ⚙️ Configuration

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

## 📊 Data Captured

The tool captures comprehensive information for each URL. The database uses a **normalized star schema** with a fact table (`url_status`) and multiple dimension/junction tables for multi-valued fields.

**Data Types:**
- **HTTP/HTTPS**: Status codes, response times, headers (security and general), redirect chains
- **TLS/SSL**: Certificate details, cipher suite, key algorithm, certificate OIDs, SANs
- **DNS**: NS, TXT, MX records; SPF and DMARC policies; reverse DNS
- **HTML**: Title, meta tags, structured data (JSON-LD, Open Graph, Twitter Cards), analytics IDs, social media links
- **Technology Detection**: CMS, frameworks, analytics tools detected via Wappalyzer rulesets
- **GeoIP**: Geographic location (country, region, city, coordinates) and network information (ASN)
- **WHOIS**: Domain registration information (registrar, creation/expiration dates, registrant info)
- **Security**: Security headers, security warnings, certificate validation

For detailed table descriptions and schema information, see [DATABASE.md](DATABASE.md).

## 📊 Database Schema

The database uses a **star schema** design pattern with:
- **Fact Table**: `url_status` (main URL data)
- **Dimension Table**: `runs` (run-level metadata)
- **Junction Tables**: Multi-valued fields (technologies, headers, DNS records, etc.)
- **One-to-One Tables**: `url_geoip`, `url_whois`
- **Failure Tracking**: `url_failures` with related tables for error context (redirect chains, request/response headers)

**Key Features:**
- WAL mode for concurrent reads/writes
- UPSERT semantics: `UNIQUE (final_domain, timestamp)` ensures idempotency
- Comprehensive indexes for fast queries
- Normalized structure for efficient storage and analytics

For complete database schema documentation including entity-relationship diagrams, table descriptions, indexes, constraints, and query examples, see [DATABASE.md](DATABASE.md).

## 📊 Output

The tool provides detailed logging with progress updates and error summaries:

**Plain format (default):**
```plaintext
✔️ domain_status [INFO] Processed 88 lines in 128.61 seconds (~0.68 lines/sec)
✔️ domain_status [INFO] Run statistics: total=100, successful=88, failed=12
✔️ domain_status [INFO] Error Counts (21 total):
✔️ domain_status [INFO]    Bot detection (403 Forbidden): 4
✔️ domain_status [INFO]    Process URL timeout: 3
✔️ domain_status [INFO]    DNS NS lookup error: 2
...
```

**Performance Analysis (`--show-timing`):**

Use the `--show-timing` flag to display detailed timing metrics:

```bash
domain_status urls.txt --show-timing
```

Example output:
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

**JSON format (`--log-format json`):**
```json
{"ts":1704067200000,"level":"INFO","target":"domain_status","msg":"Processed 88 lines in 128.61 seconds (~0.68 lines/sec)"}
```

**Note:** Performance varies significantly based on rate limiting, network conditions, target server behavior, and error handling. Expect 0.5-2 lines/sec with default settings. Higher rates may trigger bot detection.

## 🚀 Performance & Scalability

- **Concurrent Processing**: Default 30 concurrent requests (configurable via `--max-concurrency`)
- **Adaptive Rate Limiting**: Automatic RPS adjustment based on error rates (always enabled)
  - Starts at initial RPS (default: 15)
  - Monitors 429 errors and timeouts in a sliding window
  - Automatically reduces RPS by 50% when error rate exceeds threshold (default: 20%)
  - Gradually increases RPS by 15% when error rate is below threshold
  - Maximum RPS capped at 2x initial value
- **Resource Efficiency**: Shared HTTP clients, DNS resolver, and HTML parser instances
- **Database Optimization**: SQLite WAL mode for concurrent writes, indexed queries
- **Memory Safety**: Response body size capped at 2MB, redirect chains limited to 10 hops
- **Timeout Protection**: Per-URL processing timeout (35 seconds) prevents hung requests

**Retry & Error Handling:**
- **Automatic Retries**: Exponential backoff (initial: 500ms, max: 15s, max attempts: 3)
- **Error Rate Limiting**: Monitors error rate and automatically throttles when threshold exceeded
- **Processing Statistics**: Comprehensive tracking with errors, warnings, and info metrics
- **Graceful Degradation**: Invalid URLs skipped, non-HTML responses filtered, oversized responses truncated

## 🛠️ Technical Details

**Dependencies:**
- **HTTP Client**: `reqwest` with `rustls` TLS backend
- **DNS Resolution**: `hickory-resolver` (async DNS with system config fallback)
- **Domain Extraction**: `tldextract` for accurate domain parsing (handles multi-part TLDs correctly)
- **HTML Parsing**: `scraper` (CSS selector-based extraction)
- **TLS/Certificates**: `tokio-rustls` and `x509-parser` for certificate analysis
- **Technology Detection**: Custom implementation using Wappalyzer rulesets with JavaScript execution via `rquickjs`
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

## License

MIT License - see [LICENSE](LICENSE) file for details.
