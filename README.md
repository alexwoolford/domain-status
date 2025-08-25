# domain_status

[![Rust](https://github.com/alexwoolford/domain_status/actions/workflows/rust.yml/badge.svg)](https://github.com/alexwoolford/domain_status/actions/workflows/rust.yml)

**domain_status** is a Rust-based tool designed for high-performance concurrent checking of URL statuses and redirections. Built with async/await (Tokio), it processes URLs efficiently while capturing comprehensive metadata including TLS certificates, HTML content, DNS information, and redirect chains.

## 🌟 Features

* **High-Performance Concurrency**: Utilizes async/await with configurable concurrency limits (default: 500 concurrent requests)
* **Comprehensive URL Analysis**: Captures HTTP status, response times, HTML metadata, TLS certificates, DNS information, and complete redirect chains
* **Intelligent Error Handling**: Automatic retries with exponential backoff, error rate monitoring with dynamic throttling, and detailed error categorization
* **Rate Limiting**: Optional token-bucket rate limiting to control request rates and prevent overwhelming target servers
* **Robust Data Storage**: SQLite database with WAL mode, UPSERT semantics, and unique constraints for idempotent processing
* **Flexible Configuration**: Extensive CLI options for logging, timeouts, concurrency, rate limits, and database paths
* **Security Features**: URL validation (http/https only), content-type filtering, response size limits, and redirect hop limits

## 🔧 Getting Started

### Building
To get started, first build the project:

    cargo build --release

This creates an executable in the `./target/release/` directory.

### Usage

**Basic usage:**
```bash
domain_status urls.txt
```

**With custom options:**
```bash
domain_status urls.txt \
  --db-path ./results.db \
  --max-concurrency 100 \
  --timeout-seconds 15 \
  --log-level debug \
  --log-format json \
  --rate-limit-rps 10 \
  --rate-burst 50
```

**Command-line Options:**
- `--error-rate <RATE>`: Error rate threshold percentage for throttling (default: 60.0)
- `--log-level <LEVEL>`: Log level: `error`, `warn`, `info`, `debug`, or `trace` (default: `info`)
- `--log-format <FORMAT>`: Log format: `plain` or `json` (default: `plain`)
- `--db-path <PATH>`: SQLite database file path (default: `./url_checker.db`)
- `--max-concurrency <N>`: Maximum concurrent requests (default: 500)
- `--timeout-seconds <N>`: Per-request timeout in seconds (default: 10)
- `--user-agent <STRING>`: HTTP User-Agent header value (default: Chrome user agent)
- `--rate-limit-rps <N>`: Requests per second rate limit, 0 disables (default: 0)
- `--rate-burst <N>`: Rate limit burst capacity, defaults to max concurrency if 0 (default: 0)

**URL Input:**
- URLs can be provided with or without `http://` or `https://` prefix
- If no scheme is provided, `https://` is automatically prepended
- Only `http://` and `https://` URLs are accepted; other schemes are rejected
- Invalid URLs are skipped with a warning

### Data Captured

The tool captures comprehensive information for each URL:

| Field                   | Description                                                    |
|-------------------------|----------------------------------------------------------------|
| `domain`                | Initial domain extracted from the original URL                |
| `final_domain`          | Final domain after following all redirects                     |
| `ip_address`            | IP address resolved via DNS (hickory-resolver)                 |
| `reverse_dns_name`      | Reverse DNS (PTR) record for the IP address                    |
| `status`                | HTTP status code (e.g., 200, 301, 404)                          |
| `status_description`    | Human-readable HTTP status description                          |
| `response_time`         | Time taken to get the response in seconds                      |
| `title`                 | HTML `<title>` tag content                                      |
| `keywords`              | Meta keywords from `<meta name="keywords">` (comma-separated) |
| `description`           | Meta description from `<meta name="description">`              |
| `linkedin_slug`         | LinkedIn company slug extracted from LinkedIn URLs in the page |
| `security_headers`      | JSON object containing security headers (CSP, HSTS, X-Frame-Options, etc.) |
| `tls_version`           | TLS version used (e.g., TLSv1.3) - only for HTTPS            |
| `ssl_cert_subject`      | SSL certificate subject (CN, O, etc.) - only for HTTPS         |
| `ssl_cert_issuer`       | SSL certificate issuer - only for HTTPS                        |
| `ssl_cert_valid_from`   | Certificate validity start timestamp (milliseconds since epoch)  |
| `ssl_cert_valid_to`     | Certificate validity end timestamp (milliseconds since epoch)   |
| `oids`                  | JSON array of certificate policy OIDs from the SSL certificate |
| `is_mobile_friendly`    | Boolean indicating mobile-friendliness (viewport meta tag present) |
| `timestamp`            | Unix timestamp (milliseconds) when the data was captured        |
| `redirect_chain`       | JSON array of URLs in the redirect chain (from initial to final) |

**Notes:**
- TLS/SSL fields are `NULL` for HTTP (non-HTTPS) URLs
- The database uses UPSERT semantics: duplicate `(final_domain, timestamp)` pairs update existing records
- Response body size is capped at 2MB to prevent memory exhaustion
- Only HTML content-types are processed (others are skipped)
- Maximum redirect hops: 10 (prevents infinite loops)

## 📊 Output

The tool provides detailed logging with progress updates and error summaries:

**Plain format (default):**
```plaintext
✔️ domain_status::database [INFO] Database file created successfully.
✔️ domain_status [INFO] Processed 1506 lines in 5.33 seconds (~282.29 lines/sec)
✔️ domain_status [INFO] Processed 1851 lines in 10.32 seconds (~179.39 lines/sec)
✔️ domain_status [INFO] Processed 1856 lines in 15.23 seconds (~121.87 lines/sec)
✔️ domain_status [INFO] Error Counts:
✔️ domain_status [INFO]    HTTP request redirect error: 2
✔️ domain_status [INFO]    HTTP request timeout error: 154
✔️ domain_status [INFO]    HTTP request other error: 544
✔️ domain_status [INFO]    Title extract error: 49
✔️ domain_status [INFO]    Process URL timeout: 144
```

**JSON format (`--log-format json`):**
```json
{"ts":1704067200000,"level":"INFO","target":"domain_status","msg":"Processed 1506 lines in 5.33 seconds (~282.29 lines/sec)"}
```

**Error Rate Throttling:**
When the error rate exceeds the threshold (default 60%), the tool automatically throttles requests:
```plaintext
⚠️ domain_status [WARN] Throttled; error rate of 65.23% has exceeded the set threshold. There were 1234 errors out of 1892 operations. Backoff time is 13.05 seconds.
```

## 🔄 Retry & Error Handling

- **Automatic Retries**: Failed requests are automatically retried with exponential backoff
  - Initial delay: 1 second
  - Backoff factor: 2x per retry
  - Maximum delay: 20 seconds
- **Error Rate Limiting**: Monitors error rate and automatically throttles when threshold is exceeded
- **Error Categorization**: Tracks 15+ different error types (timeouts, DNS failures, HTTP errors, parsing errors, etc.)
- **Graceful Degradation**: Invalid URLs are skipped, non-HTML responses are filtered, oversized responses are truncated

## 🚀 Performance & Scalability

- **Concurrent Processing**: Default 500 concurrent requests (configurable via `--max-concurrency`)
- **Resource Efficiency**: Shared HTTP clients, DNS resolver, and HTML parser instances
- **Database Optimization**: SQLite WAL mode for concurrent writes, indexed queries
- **Memory Safety**: Response body size capped at 2MB, redirect chains limited to 10 hops
- **Timeout Protection**: Per-URL processing timeout (default 10 seconds) prevents hung requests

**System Requirements:**
- If you encounter system-specific errors related to file limits, check and adjust your system's `ulimit` settings
- For very large datasets, consider using `--rate-limit-rps` to avoid overwhelming target servers

## 🛠️ Technical Details

**Dependencies:**
- **HTTP Client**: `reqwest` with `rustls` TLS backend (no native TLS)
- **DNS Resolution**: `hickory-resolver` (async DNS with system config fallback)
- **Domain Extraction**: `publicsuffix` for accurate domain parsing
- **HTML Parsing**: `scraper` (CSS selector-based extraction)
- **TLS/Certificates**: `tokio-rustls` and `x509-parser` for certificate analysis
- **Database**: `sqlx` with SQLite (WAL mode enabled)
- **Async Runtime**: Tokio

**Architecture:**
- Async/await throughout for non-blocking I/O
- Shared resource instances (HTTP clients, DNS resolver) for efficiency
- Token-bucket rate limiting for request throttling
- Error rate monitoring with dynamic backoff
- Graceful shutdown of background tasks
