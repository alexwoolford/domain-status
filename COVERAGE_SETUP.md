# Code Coverage Setup Guide

This document explains how code coverage is configured and how to use it.

## Overview

Code coverage is implemented using:
- **cargo-tarpaulin**: Rust code coverage tool
- **Codecov**: Coverage reporting and badge service

## CI Integration

Coverage is automatically calculated in the GitHub Actions CI pipeline:

1. **Installation**: `cargo-tarpaulin` is installed in the CI environment
2. **Execution**: Coverage is generated with `cargo tarpaulin --out Xml --output-dir coverage --all-features --all-targets`
3. **Upload**: Results are uploaded to Codecov using the `codecov-action`

## Local Usage

### Install cargo-tarpaulin

```bash
cargo install cargo-tarpaulin --locked
```

### Generate Coverage Report

```bash
# Generate XML report (for CI/Codecov)
cargo tarpaulin --out Xml --output-dir coverage --all-features --all-targets

# Generate HTML report (for local viewing)
cargo tarpaulin --out Html --output-dir coverage --all-features --all-targets

# View HTML report
open coverage/tarpaulin-report.html
```

### View Coverage Summary

```bash
# Terminal output (default)
cargo tarpaulin --all-features --all-targets
```

## Codecov Setup

### 1. Sign Up for Codecov

1. Go to [codecov.io](https://codecov.io)
2. Sign in with your GitHub account
3. Add the `domain_status` repository

### 2. Get Codecov Token

1. Go to your repository settings on Codecov
2. Copy the repository upload token
3. Add it as a GitHub secret: `CODECOV_TOKEN`

### 3. Add GitHub Secret

1. Go to your GitHub repository
2. Settings → Secrets and variables → Actions
3. Click "New repository secret"
4. Name: `CODECOV_TOKEN`
5. Value: Your Codecov upload token (from step 2)

### 4. Badge URL

The coverage badge is automatically added to the README:

```markdown
[![codecov](https://codecov.io/gh/alexwoolford/domain_status/branch/main/graph/badge.svg)](https://codecov.io/gh/alexwoolford/domain_status)
```

## Coverage Targets

As specified in `AGENTS.md`:
- **Overall coverage**: ≥70%
- **Critical paths**: ≥90% (URL processing, error handling, database operations)

## Troubleshooting

### Coverage Job Fails

- Check that `CODECOV_TOKEN` secret is set in GitHub
- Verify repository is added to Codecov
- Check CI logs for specific error messages

### Coverage Percentage Not Updating

- Ensure coverage job runs on `main` branch pushes
- Check Codecov dashboard for upload status
- Verify badge URL points to correct branch (`main`)

### Local Coverage Differs from CI

- Ensure same Rust version (`stable`)
- Use `--all-features --all-targets` flags
- Check for platform-specific code (CI runs on Linux)

## Files Generated

- `coverage/cobertura.xml`: XML report for Codecov
- `coverage/tarpaulin-report.html`: HTML report for local viewing
- Both are gitignored (see `.gitignore`)

