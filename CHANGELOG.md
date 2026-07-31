# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.27] - 2026-07-31

### Removed
- Tables `url_security_warnings`, `url_body_domains`, and `url_failure_request_headers` (migration `0012_drop_deprecated_satellites.sql`). Derive former security-warning signals from `url_status` / `url_security_headers` (see DATABASE.md / QUERIES.md §30).
- Export columns `security_warnings` and `security_warning_count` (**breaking** for consumers of those fields).
- `analyze_security` / `SecurityWarning` analysis path (findings were only persisted to the dropped table).

### Added
- Shared cache root (`--cache-dir` / `DOMAIN_STATUS_CACHE_DIR` / platform cache dir + `domain_status/`) for fingerprints, GeoIP, WHOIS, and User-Agent data.
- `--no-whois` to force-disable WHOIS when enabled via TOML/env.
- Slim end-user docs: SQLite-first [README](README.md), [docs/CLI.md](docs/CLI.md), [docs/ADVANCED.md](docs/ADVANCED.md).
- `DOMAIN_STATUS_LOG_FILE` env binding for `--log-file` (parity with db/cache env vars).
- Clap `env=` bindings for remaining scan knobs (`MAX_CONCURRENCY`, `TIMEOUT_SECONDS`, `USER_AGENT`, `RATE_LIMIT_RPS`, `FINGERPRINTS`, `GEOIP`, `ENABLE_WHOIS`, `FAIL_ON`, `FAIL_ON_PCT_THRESHOLD`, `DRAIN_TIMEOUT_SECS`) so `--help` matches env behavior.

### Changed
- Config file path: CLI `--config` wins over `DOMAIN_STATUS_CONFIG_FILE` (matches documented precedence).
- `--log-format` now applies to the scan `--log-file` (plain or JSON lines); prefer `-v`/`-q` for verbosity.
- Default cache locations moved off cwd-relative `.fingerprints_cache` / `.geoip_cache` / `.whois_cache` / `.user_agent_cache` into the shared root subdirs (Linux `~/.cache/domain_status`, macOS `~/Library/Caches/domain_status`, Windows `%LOCALAPPDATA%\domain_status`).
- Startup logs the resolved cache root; superseded fingerprint hash dirs are pruned after a successful cache write; GeoIP cleans orphaned `.*.tmp` staging files on init.
- `DOMAIN_STATUS_FAIL_ON` / TOML `fail_on` accept CLI-style `any-failure` (plus `any_failure` / `anyfailure`); invalid bools in file/env are skipped instead of forced false.
- Single `DEFAULT_USER_AGENT` owned by `domain_status_cli` and re-exported from the library.
- [docs/CLI.md](docs/CLI.md) scan config matrix (flag / env / TOML / default).

## [0.1.26] - 2026-07-25

### Added
- Adversarial / offline orchestration tests: UPSERT satellite cleanup, implies fixed-point + exclude, offline `run_scan` with local fingerprints, config merge fail_on contracts, partial-failure accounting, fast concurrency smoke.
- [`docs/TESTING.md`](docs/TESTING.md): what default CI proves vs ignored/e2e, and that coverage is informational.

### Changed
- Soft-skip / discarded-result tests in `run` and fingerprint detection made honest (assert errors, local fingerprints, or `#[ignore]` with reason).
- Public API hygiene: removed `database` shim; `initialization` is crate-private; most config constants/header names are crate-private (kept `DEFAULT_USER_AGENT`, `WHOIS_TIMEOUT_SECS`, `DB_PATH`).
- ADR 0001 documents vendored fingerprint fallback.
- IP-literal hosts are accepted as domain keys in `extract_domain` (enables wiremock/httpmock CI scans; production SSRF still blocks private IPs before fetch).

### Fixed
- **CI Lint**: crate-private `initialization` rustdoc examples marked `ignore` (same pattern as resolver/rate_limiter).
- **CI macOS fingerprint tests**: do not cache vendored minimal ruleset under the remote cache key; serialize first ruleset load; skip full-corpus matcher tests when only `bundled-minimal` is available.
- **CI E2E mock scan**: expect `/favicon.ico` after IP hosts became valid domain keys.

## [0.1.25] - 2026-07-23

### Fixed
- **CI GeoIP timing flake**: `test_init_geoip_background_asn_task_doesnt_block` no longer uses a missing path (which could trigger MaxMind auto-download when `MAXMIND_LICENSE_KEY` is set by parallel tests). It now uses an existing invalid `.mmdb` fixture so the <1s assertion stays reliable.

## [0.1.24] - 2026-07-23

### Fixed
- **GeoIP skipped when `--geoip` path is missing**: if `--geoip` points at a local file that does not exist and `MAXMIND_LICENSE_KEY` is set, fall back to the same GeoLite2-City auto-download/cache path used when `--geoip` is omitted (instead of disabling GeoIP).

### Changed
- README GeoIP troubleshooting notes the missing-path fallback and recommends omitting `--geoip` when relying on `MAXMIND_LICENSE_KEY`.

## [0.1.23] - 2026-07-23

### Fixed
- **Exposed-secret false positives (web)**: hardened `generic-api-key` for minified JS (reject expressions/identifiers; raise entropy/shape requirements), restricted `--scan-external-scripts` to first-party bundles (same eTLD+1, CDN denylist), tightened Sourcegraph to `sgp_`-prefixed tokens only, and added allowlists for jsencrypt PEM templates, Angular Basic-auth docs examples, vault camelCase CSS tokens, DB URI template literals, and Sentry/YouTube credential-URL noise.
- **Public client key triage**: downgraded `gcp-api-key` severity from medium to low (Maps/Firebase client keys are public-by-design).
- **CI**: allowlisted secret-detection fixtures in `src/parse/gitleaks.rs` and avoided clippy `format_in_format_args` in overlay tests.

### Changed
- `--scan-external-scripts` now means first-party script bundles only; third-party CDNs (Stripe.js, Cookiebot, Google Analytics, etc.) are skipped.

## [0.1.22] - 2026-07-21

### Fixed
- **Secret detection false negatives (global allowlist)**: the global allowlist pattern `(?i)^true|false|null$` was mis-anchored — the `false` alternative was unanchored — and was tested against the surrounding context window, not just the matched value. Any secret near the token `false` (i.e. most JS/JSON) was silently suppressed for every rule. Fixed the pattern to `^(?i:true|false|null)$` and restricted the global allowlist to the matched value only.
- **Secret detection false negatives (minified pages)**: `line_containing` returned the entire body for newline-free (minified) documents, so a single benign `regexTarget="line"` allowlist token (e.g. a Cloudflare `data-cfemail=` widget) suppressed every real finding of that rule page-wide. The line window is now capped to 512 bytes per side of the match.
- **Secret detection false negatives (trailing boundary)**: ~150 bundled rules required the character after the secret to be a quote/space/semicolon/newline/EOL, missing keys embedded in URLs (`?key=AIza...&`) and JWTs in query strings. The trailing boundary is now relaxed at load time to also accept web delimiters (`& , ) ] } > < / ? #`).
- **Secret detection coverage (oversized content)**: pages larger than 2 MB and external scripts larger than 1 MB had their entire body discarded before scanning. The buffered prefix is now scanned instead.
- **Secret detection coverage (response headers)**: HTTP response headers and `Set-Cookie` values (e.g. `Authorization: Bearer <jwt>`, session/JWT cookies) were never scanned. They are now scanned and tagged `location=response_header`.
- **CI Security Audit**: resolved the dependency advisories that failed the audit job on every run (RUSTSEC-2026-0118/0119 via `hickory-resolver` 0.25→0.26, plus `quinn-proto`, `crossbeam-epoch`, `anyhow`, and the yanked `spin`), migrating to the hickory 0.26 API.
- **CI Code Coverage flake**: replaced the wall-clock timing assertion in `test_get_or_compile_regex_caching` (flaked under tarpaulin instrumentation) with a cache-state assertion.

### Added
- FP/FN regression corpus (`src/parse/secrets_corpus.rs`): fixtures asserting detection in the awkward web contexts that previously caused false negatives, and zero detections on benign markup (Cloudflare email-protection, `wp-content` hashes, UUIDs, SRI integrity hashes, placeholder/example keys).

### Removed
- Orphan `src/test_secret_detection.rs` (an unreferenced one-line file holding a stray fake key).

## [0.1.21] - 2026-03-13

### Fixed
- **Panic on non-standard HTTP status codes**: Servers returning non-standard codes outside the 100–599 range (e.g. HTTP 702) caused `unwrap_err()` panic because reqwest's `error_for_status()` only returns `Err` for 400–599. Changed the 5xx check from `>= 500` to `500..600` so non-standard codes are processed as normal observations.

## [0.1.20] - 2026-03-12

### Fixed
- **UTF-8 panic in secret scanner**: `extract_context` panicked when byte arithmetic (`start - 80`) landed inside a multi-byte UTF-8 character (e.g. Polish `ę`). This crashed a 2-day scan at 3% through 873K URLs. Now uses `is_char_boundary()` scan to find safe slice points.
- **Documentation accuracy audit**: DATABASE.md, QUERIES.md, and README.md updated to match current schema (migrations 0001–0008). Added missing `url_jwt_claims` table, fixed duplicate query numbering, corrected library import path, added `skipped_urls` to run history queries, documented `UNIQUE(run_id, final_domain)` constraint.

### Added
- Regression test `test_context_multibyte_boundary_no_panic` to prevent future UTF-8 boundary panics in the secret scanner.

## [0.1.19] - 2026-03-12

### Added
- **OSINT Tier 1**: body SHA-256 hash, content-length, HTTP version, word/line count, content-type, canonical URL, certificate fingerprint SHA-256, redirect chain status codes per hop.
- **OSINT Tier 2**: CNAME records, AAAA (IPv6) addresses, CAA (Certificate Authority Authorization) records. All stored in normalized satellite tables.
- **OSINT Tier 3**: CSP domain extraction, cookie security analysis (Secure/HttpOnly/SameSite), meta refresh detection, preconnect/dns-prefetch resource hints, body FQDN extraction (using scraper HTML parser, not regex), certificate intelligence (serial number, self-signed/wildcard/mismatched detection).
- New satellite tables: `url_cname_records`, `url_ipv6_addresses`, `url_caa_records`, `url_csp_domains`, `url_cookies`, `url_resource_hints`, `url_body_domains`.
- Structured `TechnologyRecord` and `AnalyticsIdRecord` in JSONL export (avoids comma/colon delimiter corruption).
- Reference repos: cloned `cdncheck` and `dnsx` for future CDN detection work.

### Fixed
- **4xx responses now processed as successes**: 403 Forbidden (WAF/bot detection) pages are fully scanned instead of discarded. Only 429 and 5xx trigger the failure/retry path.
- **Drain timeout accounting**: in-flight tasks aborted during shutdown are now counted as failed instead of silently dropped (91+9=100, not 89+7=96).
- **Stale satellite data on UPSERT**: all 26 satellite/enrichment tables are now cleaned before re-inserting, preventing corrupted merges when the same domain is rescanned.
- **Regex ternary `\10` corruption**: `replace_placeholders` now iterates in reverse (high to low), matching `extract_version_from_template`.
- **Regex pattern destruction**: `.to_lowercase()` was applied to Wappalyzer regex patterns, converting `\S` to `\s` and `\D` to `\d`. Now only header/cookie keys are lowercased.
- **CSV column misalignment**: data array order now matches header order for all 84 columns.
- **TXT record truncation panic**: byte-index slicing replaced with `.chars().take(N)` to respect UTF-8 boundaries.
- **WHOIS cache quota bypass**: counter now seeded from actual directory size on restart.
- **Certificate mismatch false positives**: comparison used already-drained SAN list (always empty). Now uses the correct `sans_vec`.
- **NULL registrable_domain**: bare PSL suffixes (e.g., `akamaihd.net`) now fall back to the FQDN itself.
- **Percent-encoded contact values**: `tel:` and `mailto:` hrefs are now URL-decoded.
- **Resource hints stored raw URLs**: now stores clean hostnames only.
- **Double/triple DOM parse**: body domain extraction and mobile-friendliness check now reuse the existing DOM tree.
- **JSON-LD regex recompilation**: two complex regexes now compiled once via `static LazyLock`.
- **Unbounded text allocation**: `.collect()` on full page text replaced with iterator early termination.
- **Status server double-counted skipped URLs**: `processed = completed + failed` (completed already includes skipped).
- **Ctrl-C cancellation**: active HTTP requests now aborted immediately via `tokio::select!` instead of waiting for drain timeout.
- **Export data trapped**: Tier 3 satellite counts (CSP, cookies, hints, body domains) now fetched from DB instead of hardcoded 0.

### Removed
- `url-list.txt` and `url-list.txt` removed from git tracking (user-specific data).

## [0.1.18] - 2026-03-11

### Changed
- SSRF: consolidate private IP checks into `url_validation`; add missing ranges (CGNAT 100.64.0.0/10, benchmarking 198.18.0.0/15, IETF 192.0.0.0/24, documentation 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). `safe_resolver` now uses shared `is_private_ip`.
- Retry logic: replace fragile string matching in `is_retriable_error` with typed `hickory_resolver::ResolveError` downcast for DNS; rely on `reqwest::Error::status()` for HTTP.
- ProcessingStats: use `enum_map::EnumMap` instead of `HashMap<ErrorType, AtomicUsize>`; consistent `Ordering::Relaxed` for stats.
- Hot path: use `Ordering::Relaxed` for independent atomic counters in run/task.
- Task handlers: reduce argument count via `TaskProgress` struct; remove `clippy::too_many_arguments` suppressions.
- Redirect chain: O(1) check `chain.last() != Some(&last_fetched_url)` instead of `chain.contains()`.
- HTTP client: tune pool_idle_timeout, pool_max_idle_per_host, tcp_nodelay for scanning.
- SQLite: set `PRAGMA synchronous=NORMAL` with WAL mode.

## [0.1.17] - 2026-03-10

### Changed
- CI: remove unused `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` env var (no effect on Node 20 deprecation warnings).

## [0.1.16] - 2026-03-09

### Security
- Fix RUSTSEC-2026-0037: update `quinn-proto` 0.11.13 → 0.11.14 (DoS in Quinn endpoints, severity 8.7).

### Changed
- Remove redundant `webpki-roots` dependency (already transitive via reqwest).
- Move tokio `test-util` feature to dev-dependencies (not needed in release builds).
- Replace `panic!` with `log::error!` in failure recording to prevent scan crashes on transient DB errors.

## [0.1.15] - 2026-03-09

### Changed
- Multi-channel release: version bump for GitHub, Homebrew, and Crates.io distribution.

## [0.1.14] - 2026-03-08

### Added
- Impactful adversarial and boundary tests for run/task, cli, favicon, geoip, fetch/handler, and vendor whois-service (contracts, failure paths, threshold boundaries).

### Changed
- **Timing fields**: Internal duration fields renamed from `_ms` to `_us` where they store microseconds (`UrlTimingMetrics`, `TimingStats`, and status server timing). Epoch/timestamp columns (e.g. `start_time_ms`, `observed_at_ms`) remain in milliseconds; no database migration. Public API (e.g. `/status` JSON) still reports times in milliseconds.

## [0.1.12] - 2026-03-02

### Added
- **Contact extraction**: Extract email addresses and phone numbers from `mailto:` and `tel:` links in HTML. New `url_contact_links` table with deduplication.
- **Exposed secret detection**: Scan HTML for ~57 credential patterns across 13 categories (AWS, OpenAI, Anthropic, Stripe, Slack, GitHub, GitLab, database URLs, private keys, and many more). Each finding includes:
  - **Severity classification** (critical/high/medium/low) based on impact
  - **Location heuristic** (inline_script, html_comment, data_attribute, url_parameter, meta_tag, html_body)
  - **80-character context window** for analyst triage
  - Full matched values stored (no redaction — these are on the public web)
- New `url_exposed_secrets` table with severity and location columns
- **Homebrew tap**: `brew tap alexwoolford/domain-status && brew install domain_status`
- Per-domain rate limiting (`--max-per-domain`) to prevent overwhelming individual servers
- Parquet export format with Apache Arrow typed columns
- Complete export data: all satellite table data now included in CSV/JSONL/Parquet exports

### Fixed
- `.gitignore` `secrets.*` pattern was blocking `secrets.rs` source files
- Flaky `test_regex_cache_works` timing assertion on macOS CI runners
- Retry default changed to fail-fast for unknown errors (was incorrectly retrying)

## [0.1.11] - 2026-02-18

### Added
- Resource limits: MAX_TXT_RECORD_COUNT (20) to prevent DNS record abuse
- Resource limits: MAX_WHOIS_CACHE_ENTRIES (50K) with LRU eviction to cap disk usage
- SQLite retry module with exponential backoff for SQLITE_BUSY/LOCKED errors
- Comprehensive tests for retry logic, TXT record limits, and WHOIS cache eviction

### Changed
- Standardized all dependency versions to ^x.y format for consistent patch updates
- Simplified constant validation tests by removing redundant assertions
- Refactored run_scan module to reduce complexity
- Introduced type-safe enums for export functionality

### Fixed
- Clippy warnings: too_many_lines, assertions_on_constants, identity_op
- Documentation: Fixed broken links and improved clarity

### Dependencies
- Updated futures: 0.3.31 → 0.3.32 (performance improvements)
- Updated clap: 4.5.57 → 4.5.59 (bug fixes)
- Updated env_logger: 0.11.8 → 0.11.9
- Updated maxminddb: 0.27.1 → 0.27.3 (performance improvements)
- Updated psl: 2.1.189 → 2.1.192 (public suffix list updates)

## [0.1.10] - 2026-02-11

### Added
- Production hardening: Security limits for header count (100), TXT record size (1KB), response body (2MB), and redirect hops (10)
- Production operations guide with retention policies, concurrency tuning, and scaling strategies
- Stress tests documenting attack vectors (header bombs, DNS tunneling, database scaling, concurrency limits)
- Cancellation safety tests for async transaction handling and graceful shutdown
- Documentation on operational limits and monitoring recommendations

### Changed
- Marked slow integration tests as `#[ignore]` to prevent CI timeouts
- Distilled documentation to remove internal meta-documentation and historical narrative
- Simplified testing guide for contributors

### Fixed
- Property-based domain tests now use minimum 5-character patterns to avoid PSL edge cases
- Excluded timing-sensitive cancellation tests from coverage runs to prevent instrumentation-related failures
- Documentation inaccuracies in PRODUCTION_HARDENING.md (table names, feature status)

### Security
- Header bomb protection: Limits HTTP header count to prevent resource exhaustion
- DNS tunneling protection: TXT records capped at 1KB to prevent abuse
- Circuit breaker for database writes to handle overload gracefully
- CLI warning when concurrency exceeds connection pool size

## [0.1.6] - 2025-01-09

### Added
- **Subcommand-based CLI**: Switched to subcommand-style interface (`domain_status scan` and `domain_status export`)
- **CSV Export**: New `export` subcommand to export scan results to CSV format with comprehensive filtering options
- **Exit Code Policies**: New `--fail-on` option to control application exit codes based on scan results (`never`, `any-failure`, `pct>`)
- **Stdin Input Support**: Can now read URLs from standard input using `-` as filename
- **SQL Query Examples**: Added `QUERIES.md` with 26 common SQL queries for analyzing scan results
- Comprehensive test coverage: 20+ new high-value tests for CSV export, CLI parsing, exit codes, stdin input, and input parsing
- Export module with CSV export functionality supporting filtering by run_id, domain, status, and timestamp

### Changed
- **BREAKING**: CLI now requires explicit subcommands (`scan` or `export`). Backward compatibility removed.
- Removed 7 low-value tests that only tested Rust derive macros (Debug, Clone, Default)
- Improved test quality: removed coverage padding, focused on genuinely valuable test cases
- Updated README.md to reflect new subcommand structure

### Fixed
- Fixed clippy warnings (use `&Path` instead of `&PathBuf`, remove needless borrows, use arrays instead of `vec!`)
- Fixed test compilation errors and improved test reliability

## [0.1.5] - 2025-01-08

### Added
- Comprehensive test coverage for initialization module (client, resolver, logger)
- Test coverage for TLS certificate handling module
- Test coverage for status server HTTP endpoints (status and metrics handlers)
- Fixed bug in `query_run_history` SQL query (missing `version` column)

### Changed
- Logger initialization now uses `try_init()` instead of `init()` to handle re-initialization gracefully in tests
- TLS tests now properly initialize crypto provider before running

## [0.1.4] - 2025-12-06

Initial public release.

### Added
- High-performance concurrent URL checking with configurable limits
- Comprehensive data capture (HTTP, TLS, DNS, HTML, technology detection, GeoIP, WHOIS)
- SQLite database with normalized star schema
- Technology fingerprinting using Wappalyzer rulesets
- Adaptive rate limiting with error-based throttling
- Optional HTTP status server for monitoring long-running jobs
- Pre-commit hooks for secret scanning and code quality
- CI/CD pipeline with automated testing, security auditing, and coverage reporting
- Release infrastructure with automated binary builds for Linux, macOS, and Windows
- Embedded database migrations for distributed binaries

### Changed
- Migrated from `tldextract` to `psl` for domain extraction (better maintenance, no idna conflicts)
- Upgraded `hickory-resolver` from 0.24 to 0.25 (better security, DNSSEC validation)
- Enabled `RUST_LOG` environment variable support for flexible logging
- Requires Rust 1.85+ (for edition 2024 support in dependencies)

### Security
- Integrated `gitleaks` for secret scanning (pre-commit and CI)
- Security audit with `cargo-audit` in CI pipeline
- URL validation to prevent SSRF attacks

[Unreleased]: https://github.com/alexwoolford/domain_status/compare/v0.1.27...HEAD
[0.1.27]: https://github.com/alexwoolford/domain_status/compare/v0.1.26...v0.1.27
[0.1.26]: https://github.com/alexwoolford/domain_status/compare/v0.1.25...v0.1.26
[0.1.25]: https://github.com/alexwoolford/domain_status/compare/v0.1.24...v0.1.25
[0.1.24]: https://github.com/alexwoolford/domain_status/compare/v0.1.23...v0.1.24
[0.1.23]: https://github.com/alexwoolford/domain_status/compare/v0.1.22...v0.1.23
[0.1.22]: https://github.com/alexwoolford/domain_status/compare/v0.1.21...v0.1.22
[0.1.11]: https://github.com/alexwoolford/domain_status/compare/v0.1.10...v0.1.11
[0.1.10]: https://github.com/alexwoolford/domain_status/compare/v0.1.6...v0.1.10
[0.1.6]: https://github.com/alexwoolford/domain_status/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/alexwoolford/domain_status/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/alexwoolford/domain_status/releases/tag/v0.1.4
