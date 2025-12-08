# Testing Guide

This document explains the testing strategy for `domain_status`.

## Test Structure

The project uses a three-tier testing approach:

### 1. Unit Tests (`src/**/tests.rs`)

Fast, isolated tests that run in all CI jobs. These tests:
- Have no network dependencies
- Use mocks and stubs where needed
- Run quickly (< 1 second total)
- Cover individual functions and modules

**Run locally:**
```bash
cargo test --lib
```

### 2. Integration Tests with Mock Servers (`tests/integration_test.rs`)

Tests that use `httptest` to create mock HTTP servers. These tests:
- Verify HTTP request/response handling
- Test redirect chains
- Validate error handling
- Still run quickly (no real network calls)

**Run locally:**
```bash
cargo test --test integration_test
```

### 3. End-to-End Tests (Marked `#[ignore]`)

True end-to-end tests that require network access. These tests:
- Make real DNS lookups
- Fetch fingerprint rulesets from GitHub
- Connect to real TLS endpoints
- Verify the full pipeline works end-to-end

**Why `#[ignore]`?**
- They require network access (slow, flaky in CI)
- They depend on external services (DNS, GitHub, etc.)
- They're run separately in CI to avoid blocking regular test runs

**Run locally:**
```bash
# Run all ignored tests
cargo test -- --ignored

# Run a specific ignored test
cargo test -- --ignored test_full_scan_with_mock_server
```

## CI Test Coverage

The CI workflow (`.github/workflows/ci.yml`) runs:

1. **All unit tests** - On all platforms (Ubuntu, Windows, macOS)
2. **All integration tests** - On all platforms
3. **End-to-end tests** - Only on Ubuntu, in the `e2e` job
4. **Code formatting** - `cargo fmt --check` (Ubuntu only, platform-agnostic)
5. **Linting** - `cargo clippy --all-targets --all-features --locked -- -D warnings` (Ubuntu only)
6. **Security audit** - `cargo audit` (all platforms, also runs weekly)
7. **Secret scanning** - `gitleaks` (on code changes)

## Code Quality Checks

### Formatting

Code must be formatted with `rustfmt`:

```bash
# Check formatting
cargo fmt --check

# Auto-format
cargo fmt
```

### Linting

Code must pass `clippy` with no warnings:

```bash
# Run clippy
cargo clippy --all-targets --all-features --locked -- -D warnings
```

### Security Audit

Dependencies are audited for known vulnerabilities:

```bash
# Run security audit
cargo audit
```

Configuration: `.cargo/audit.toml`

## Writing Tests

### Unit Tests

Place unit tests in the same file as the code, in a `#[cfg(test)]` module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_my_function() {
        // Test code
    }
}
```

### Integration Tests

Place integration tests in `tests/integration_test.rs` or create new test files in `tests/`.

Use `httptest` for HTTP mocking:

```rust
use httptest::{matchers::*, responders::*, Expectation, Server};

#[tokio::test]
async fn test_http_request() {
    let server = Server::run();
    server.expect(
        Expectation::matching(request::method_path("GET", "/"))
            .respond_with(status_code(200).body("OK")),
    );

    // Test code using server.url("/")
}
```

### End-to-End Tests

Mark end-to-end tests with `#[ignore]`:

```rust
#[tokio::test]
#[ignore] // Requires network access
async fn test_real_network_request() {
    // Test code that makes real network calls
}
```

## Test Coverage

Code coverage is generated via `cargo-tarpaulin` and uploaded to Codecov:

- Coverage reports are generated on every push/PR
- View coverage at: https://codecov.io/gh/alexwoolford/domain_status
- Coverage includes all tests (unit + integration), but excludes `#[ignore]` tests

## Troubleshooting

### Tests fail locally but pass in CI

- Check if you're running ignored tests: `cargo test` vs `cargo test -- --ignored`
- Ensure you have network access for e2e tests
- Check if dependencies are up to date: `cargo update`

### Clippy warnings

Fix clippy warnings before committing:

```bash
cargo clippy --fix --all-targets --all-features
```

### Formatting issues

Auto-format before committing:

```bash
cargo fmt
```

## Best Practices

1. **Write unit tests first** - Fast, reliable, easy to debug
2. **Use mocks for external dependencies** - Don't make real network calls in unit tests
3. **Mark network-dependent tests with `#[ignore]`** - Keep regular test runs fast
4. **Test error paths** - Don't just test the happy path
5. **Keep tests independent** - Tests should not depend on each other
6. **Use descriptive test names** - `test_handle_http_error_500` is better than `test_error`
