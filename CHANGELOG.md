# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/alexwoolford/domain_status/compare/v0.1.4...HEAD
[0.1.4]: https://github.com/alexwoolford/domain_status/releases/tag/v0.1.4
