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

**Config validation:** Unit tests for `Config::validate()` live in `src/config/types.rs`. Integration tests that use config (panic safety, error message shape) are in `tests/panic_safety.rs` and `tests/error_messages.rs`; keep these minimal and non-duplicative of the unit tests.

**Stress tests:** Stress tests (`tests/stress_*.rs`) are ignored by default. Run them manually for load/resilience checks: `cargo test --test 'stress_*' -- --ignored --nocapture`.

See [.github/workflows/ci.yml](.github/workflows/ci.yml) for the full CI pipeline.
