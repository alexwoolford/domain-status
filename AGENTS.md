## AGENTS playbook: quality, robustness, and safety

This document codifies how agents and contributors should change, test, and operate `domain_status` to keep it fast, safe, and reliable.

### Architecture snapshot
- HTTP via `reqwest` and async `tokio` runtime
- DNS via `hickory-resolver` (0.24)
- HTML parsing via `scraper`
- TLS info via `tokio-rustls` and `x509-parser`
- Persistence via `sqlx` (SQLite / WAL)

### Golden rules
- Prefer safety over speed by default. Timeouts and backoffs must be enabled for any network IO.
- Concurrency must be bounded and configurable. Never remove the semaphore.
- Never add blocking calls (std::net, std::fs heavy ops) to async paths without `spawn_blocking`.
- Do not introduce `native-tls`. Prefer `rustls` for deterministic builds and fewer CVEs.
- Database schema changes must be done via migrations only (no ad-hoc CREATE/ALTER in app code).
- All code must be formatted, linted, tested, and auditable before merge.

### Local dev quickstart
```bash
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features --all-targets
cargo build --release
```

### Quality checklist (pre-merge)
- [ ] `cargo fmt` produces no diff
- [ ] `cargo clippy -- -D warnings` passes (no warnings)
- [ ] `cargo test` passes; add tests for new behavior
- [ ] Integration tests do not hit the public internet (use mocks)
- [ ] `cargo audit` shows no high/critical issues or they are justified
- [ ] No panics on the hot path; errors are handled or bubbled via `anyhow`/custom errors
- [ ] Logging is useful at `info` and not chatty at `debug`; no secrets in logs
- [ ] Dependency features are minimal; avoid enabling unused features
- [ ] If DB schema changed, add a migration and bump the app version

### File hygiene
- **NEVER commit temporary LLM-generated working files** such as:
  - `*_REVIEW.md` (e.g., `CODE_REVIEW.md`, `QUALITY_ASSESSMENT.md`, `TECHNICAL_DEBT_REVIEW.md`)
  - `*_PLAN.md` (e.g., `ARCHITECTURE_PLAN.md`)
  - `*_ASSESSMENT.md` (e.g., `QUALITY_ASSESSMENT.md`)
  - `ARCHITECTURE_EXAMPLE.md`
- These files are for LLM analysis only and should be excluded via `.gitignore`
- If you create such files during analysis, delete them before committing
- Only commit permanent documentation files: `README.md`, `AGENTS.md`, and user-requested documentation

### Dependency hygiene
- Pin to compatible minor versions, avoid wildcard (`*`).
- Prefer `default-features = false` and explicitly enable what you use.
- For `reqwest`, prefer the `rustls` backend (`rustls-tls` or `rustls-tls-native-roots`). Do not enable both `native-tls` and `rustls`.
- Periodically run:
```bash
cargo update -p <crate>
cargo audit
```

### Concurrency, timeouts, and backoff
- Default timeouts must be set for all network calls. Keep request timeout ≤ 10s.
- Keep a global semaphore; expose a CLI flag (e.g., `--max-concurrency`) to tune it.
- Use exponential backoff with a bounded max delay. Abort retriable operations when the error rate crosses the configured threshold.
- The logging heartbeat must be cancellable with `JoinHandle::abort()` during shutdown.

### Database and migrations
- Use `sqlx` migrations for any schema change. Do not embed `CREATE TABLE` definitions inline except as a guard for the very first boot.
- Create indexes for query patterns (e.g., on `domain`, `timestamp`).
- Prefer UPSERT semantics when idempotency matters (e.g., reprocessing the same URL at the same timestamp).
- WAL is required for concurrent writes.

### Datetime storage in SQLite
- **SQLite has no native datetime type** - it only supports INTEGER, TEXT, REAL, BLOB, and NULL.
- **Always use INTEGER for datetime fields** - store as milliseconds since Unix epoch (i64).
- **Conversion pattern**: Use `DateTime<Utc>::timestamp_millis()` or `NaiveDateTime::and_utc().timestamp_millis()` to convert to `i64`.
- **Consistent across the project**: All datetime fields use INTEGER (milliseconds):
  - `url_status.timestamp` → INTEGER
  - `url_status.ssl_cert_valid_from` → INTEGER
  - `url_status.ssl_cert_valid_to` → INTEGER
  - `runs.start_time` → INTEGER
  - `runs.end_time` → INTEGER
  - `url_whois.creation_date` → INTEGER
  - `url_whois.expiration_date` → INTEGER
  - `url_whois.updated_date` → INTEGER
- **Never use TEXT for datetimes** - INTEGER is more efficient for queries, sorting, and indexing.
- **Helper function**: `naive_datetime_to_millis()` in `src/storage/insert.rs` converts `Option<NaiveDateTime>` to `Option<i64>`.

### Testing policy
Tiered tests:
1) Unit tests: pure functions (HTML parsing, header extraction, domain extraction)
2) Integration tests: HTTP client behavior via a local mock server (e.g., `httptest`, `wiremock-rs`)
3) DB tests: run against a temporary SQLite file in a tempdir; assert schema and inserted rows
4) E2E smoke: optional, guarded by a feature flag and off by default to avoid external calls

Coverage targets:
- Critical parsing utilities and error mapping ≥ 90%
- Overall project coverage ≥ 70%

### Observability
- Keep `info` logs concise; reserve `debug` for verbose internals.
- Consider a structured log format (JSON) behind a `--log-format=json` flag for batch runs.
- Track counters for request outcomes and retry counts. Consider `metrics` + Prometheus in future.

### CLI contracts and defaults
- Add/configure flags for: input file, `--db-path`, `--max-concurrency`, `--timeout-seconds`, `--error-rate`, `--user-agent`, `--log-level`, `--log-format`.
- Defaults must be conservative and safe: concurrency O(32–128), timeout 10s, error-rate ≤ 50%.

### Security and compliance
- Treat all input as untrusted. Validate URLs and normalize scheme/host.
- Do not follow non-HTTP(S) schemes. Block `file:`, `ftp:`, `mailto:` etc.
- No credentialed endpoints. Never log authorization headers or cookies.
- Respect robots.txt and rate limits when expanding scope to crawl; currently this tool hits provided URLs only.

### Performance budgets
- Per-URL processing should complete within 1 network RTT + parsing; global average ≤ 500ms when healthy.
- Avoid reading full bodies for sites where only headers are needed. Consider HEAD before GET and short-circuit early when possible.
- Avoid unbounded maps/strings; cap response size (e.g., first 1–2 MB) to prevent pathological cases.

### PR checklist (copy into description)
- [ ] Tests added/updated and pass
- [ ] Lints pass with `-D warnings`
- [ ] No network calls in tests (unless `e2e` feature enabled)
- [ ] DB migrations added (if schema touched)
- [ ] CLI/README/AGENTS updated (if behavior changed)
- [ ] Logs are actionable and not overly verbose
- [ ] No temporary LLM-generated markdown files committed (e.g., `*_REVIEW.md`, `*_PLAN.md`, `*_ASSESSMENT.md`)

### CI recommendations
- Build matrix: stable (required), beta (optional)
- Steps: fmt check, clippy (`-D warnings`), tests, `cargo audit`, build release
- Cache: cargo registry + target

### Manual QA recipe (pre-release)
```bash
# 1) Run unit/integration tests
cargo test --all-features --all-targets

# 2) Lints and audit
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo audit

# 3) Smoke run on a small input
cargo build --release
./target/release/domain_status urls.txt

# 4) Inspect DB and spot-check records
sqlite3 url_checker.db "SELECT COUNT(*), MIN(status), MAX(status) FROM url_status;"
sqlite3 url_checker.db "SELECT id, domain, status, title FROM url_status ORDER BY id DESC LIMIT 5;"
```

### Future improvements (backlog hints)
- Make DB path and concurrency tunable via CLI
- Abort logging task via `JoinHandle::abort()` on shutdown
- Replace inline schema with `sqlx` migrations
- Add wiremock-based integration suite and fixtures
- Switch `reqwest` to `rustls` backend only and trim features
- Add indexes on `domain`, `timestamp`; consider UPSERT for idempotent writes
- Provide JSON log output option and metrics
