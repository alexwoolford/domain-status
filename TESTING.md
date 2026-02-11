# Testing

## Running Tests

```bash
# Run all tests (unit + integration)
cargo test

# Run end-to-end tests (requires network)
cargo test -- --ignored

# Run specific test
cargo test test_name

# Run with output
cargo test -- --nocapture
```

## Code Quality

```bash
# Format code
cargo fmt

# Check formatting
cargo fmt --check

# Run linter
cargo clippy --all-targets --all-features --locked -- -D warnings

# Security audit
cargo audit
```

## Test Structure

- **Unit tests**: In `src/**/tests.rs` modules (fast, no network)
- **Integration tests**: In `tests/*.rs` files
- **E2E tests**: Marked `#[ignore]` (run separately with `-- --ignored`)

See [.github/workflows/ci.yml](.github/workflows/ci.yml) for the full CI pipeline.
