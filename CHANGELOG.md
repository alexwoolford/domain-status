# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.6] - 2025-01-09

### Added
- **Subcommand-based CLI**: Switched to subcommand-style interface (`domain_status scan` and `domain_status export`)
- **CSV Export**: New `export` subcommand to export scan results to CSV format with comprehensive filtering options
- **Exit Code Policies**: New `--fail-on` option to control application exit codes based on scan results (`never`, `any-failure`, `pct>`, `errors-only`)
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

[Unreleased]: https://github.com/alexwoolford/domain_status/compare/v0.1.6...HEAD
[0.1.6]: https://github.com/alexwoolford/domain_status/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/alexwoolford/domain_status/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/alexwoolford/domain_status/releases/tag/v0.1.4
