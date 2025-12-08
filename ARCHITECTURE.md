# Architecture Overview

## High-Level Design

`domain_status` follows a **pipeline architecture** with concurrent processing:

```
Input File → URL Validation → Concurrent Processing → Data Extraction → Direct Database Writes → SQLite Database
```

## Core Components

### 1. Main Orchestrator (`src/lib.rs`)
- Reads URLs from input file line-by-line
- Validates and normalizes URLs (adds `https://` if missing)
- Manages concurrency via semaphore
- Coordinates initialization and graceful shutdown
- Tracks progress and statistics
- **Note**: `src/main.rs` is a thin CLI wrapper that parses arguments and calls the library

### 2. HTTP Request Handler (`src/fetch/handler/`)
- **Request Handler** (`request.rs`): Fetches URLs, follows redirects, handles retries
- **Response Handler** (`response.rs`): Extracts response data, orchestrates data collection
- Uses `reqwest` with `rustls` TLS backend
- Implements exponential backoff retry strategy
- Respects rate limiting via token bucket

### 3. Data Extraction (`src/fetch/`)
- **HTML Parsing** (`response.rs`): Extracts title, meta tags, structured data, scripts
- **Technology Detection** (`fingerprint/`): Detects web technologies using Wappalyzer rulesets
  - Runs in parallel with DNS/TLS fetching (independent operations)
  - Uses pattern matching (headers, cookies, HTML, script URLs) - **does not execute JavaScript**
- **DNS/TLS** (`dns/`): Fetches DNS records (NS, TXT, MX), TLS certificates
  - Runs in parallel with technology detection
  - DNS forward/reverse and TLS handshake run in parallel
- **Enrichment** (`record/preparation.rs`): GeoIP, WHOIS, security analysis
  - All enrichment lookups run in parallel

### 4. Database Writer (`src/storage/insert/`)
- **Direct Writes**: Records written immediately (no batching)
- **Transaction-Based**: Each URL record and its enrichment data written in a single transaction
- **SQLite WAL Mode**: Enables efficient concurrent writes
- **UPSERT Semantics**: `UNIQUE (final_domain, timestamp)` prevents duplicates

### 5. Error Handling (`src/error_handling/`)
- Categorizes errors (timeout, DNS, TLS, HTTP, etc.)
- Tracks error statistics
- Implements retry logic with exponential backoff
- Records failures in `url_failures` table

### 6. Rate Limiting (`src/adaptive_rate_limiter/`)
- Token-bucket algorithm for request rate limiting (implemented in `src/initialization/rate_limiter.rs`)
- Adaptive adjustment based on error rates
- Monitors 429 errors and timeouts
- Automatically reduces RPS by 50% when error rate exceeds threshold (default: 20%)
- Increases RPS by 15% when error rate is below threshold/2 (default: 10%)
- Maximum RPS capped at 2x initial value

## Concurrency Model

### Async Runtime
- **Tokio**: Async runtime for all I/O operations
- **Non-blocking**: All network operations are async
- **Shared Resources**: HTTP client, DNS resolver, database pool shared across tasks

### Concurrency Control
- **Semaphore**: Limits concurrent URL processing tasks (default: 30)
- **Rate Limiting**: Token-bucket limits requests per second (default: 15 RPS)
- **Adaptive Adjustment**: Rate limiter adjusts based on error rates

### Parallel Execution
The following operations run in parallel to maximize throughput:

1. **Technology Detection + DNS/TLS**: Independent operations, run simultaneously
2. **Enrichment Lookups**: GeoIP, security analysis, and WHOIS run in parallel
3. **DNS Operations**: Forward DNS, reverse DNS, and TLS handshake run in parallel

### Background Tasks
- **Status Server** (optional): HTTP server for monitoring progress
- **Adaptive Rate Limiter**: Monitors error rates and adjusts RPS
- **Logging Task**: Periodic progress updates

### Graceful Shutdown
- All background tasks cancellable via `CancellationToken`
- In-flight requests complete before shutdown
- Database connections closed cleanly

## Data Flow

### URL Processing Pipeline

1. **Input**: Read URL from file
2. **Validation**: Validate and normalize URL
3. **Rate Limiting**: Acquire token from rate limiter
4. **Concurrency Control**: Acquire semaphore permit
5. **HTTP Request**: Fetch URL, follow redirects
6. **Response Processing**:
   - Extract response data (headers, body, status)
   - Parse HTML content
   - **Parallel Operations**:
     - Technology detection (HTML-based)
     - DNS/TLS fetching (domain-based)
   - **Enrichment** (parallel):
     - GeoIP lookup (IP-based)
     - Security analysis (TLS/headers-based)
     - WHOIS lookup (domain-based)
7. **Database Write**: Insert record and all enrichment data in single transaction
8. **Cleanup**: Release semaphore permit, update statistics

## Database Schema

The database uses a **star schema** design:

- **Fact Table**: `url_status` (main URL data)
- **Dimension Table**: `runs` (run-level metadata)
- **Junction Tables**: Multi-valued fields (technologies, headers, DNS records, etc.)
- **One-to-One Tables**: `url_geoip`, `url_whois`
- **Failure Tracking**: `url_failures` with satellite tables

See [DATABASE.md](DATABASE.md) for complete schema documentation.

## Performance Optimizations

1. **Parallel Execution**: Independent operations run simultaneously
2. **Shared Resources**: HTTP client, DNS resolver, database pool reused
3. **SQLite WAL Mode**: Enables concurrent writes without locking
4. **Direct Writes**: No batching overhead (WAL mode handles concurrency)
5. **Bounded Concurrency**: Semaphore prevents resource exhaustion
6. **Adaptive Rate Limiting**: Automatically adjusts to avoid bot detection
7. **Efficient Caching**: Fingerprint rulesets, GeoIP databases, User-Agent cached locally

## Error Handling Strategy

1. **Retry Logic**: Exponential backoff for transient errors
2. **Error Categorization**: Different error types handled differently
3. **Partial Failures**: DNS/TLS errors don't prevent URL processing
4. **Circuit Breaker**: Database write failures trigger circuit breaker
5. **Graceful Degradation**: Invalid URLs skipped, non-HTML responses filtered

## Security Considerations

1. **URL Validation**: Only `http://` and `https://` URLs accepted
2. **Content Filtering**: Non-HTML responses filtered
3. **Size Limits**: Response bodies capped at 2MB
4. **Redirect Limits**: Maximum 10 redirect hops
5. **JavaScript Execution**: **Not performed** - uses pattern matching only (matches WappalyzerGo behavior)
6. **TLS**: Uses `rustls` (no native TLS dependencies)
