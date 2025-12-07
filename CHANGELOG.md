# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release with core URL checking functionality
- High-performance concurrent processing with configurable limits
- Comprehensive data capture (HTTP, TLS, DNS, HTML, technology detection, GeoIP, WHOIS)
- SQLite database with normalized star schema
- Technology fingerprinting using Wappalyzer rulesets
- Adaptive rate limiting with error-based throttling
- Optional HTTP status server for monitoring long-running jobs
- Pre-commit hooks for secret scanning and code quality
- CI/CD pipeline with automated testing, security auditing, and coverage reporting

### Changed
- Migrated from `tldextract` to `psl` for domain extraction (better maintenance, no idna conflicts)
- Upgraded `hickory-resolver` from 0.24 to 0.25 (better security, DNSSEC validation)
- Enabled `RUST_LOG` environment variable support for flexible logging

### Security
- Integrated `gitleaks` for secret scanning (pre-commit and CI)
- Security audit with `cargo-audit` in CI pipeline
- URL validation to prevent SSRF attacks

## [0.1.1] - 2025-12-06

### Fixed
- Constrained `base64ct` to 1.8.0 to avoid edition 2024 requirement (fixes `cargo install` on older Rust toolchains)

## [0.1.0] - 2025-12-06

Initial release.

### Fixed
- Embedded database migrations into binary to fix "No such file or directory" error in distributed binaries
- Fixed release workflow archive paths and artifact upload issues

[Unreleased]: https://github.com/alexwoolford/domain_status/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/alexwoolford/domain_status/releases/tag/v0.1.0
