# Developer task runner for domain_status
# Install: cargo install just
# Run: just <command>

# Default recipe shows available commands
default:
    @just --list

# Run all checks (formatting, linting, docs, tests)
# Matches the Lint + Test Suite gates that catch most CI surprises locally.
check: fmt lint docs-check test
    @echo "✅ All checks passed!"

# Format code
fmt:
    cargo fmt

# Check formatting without modification
fmt-check:
    cargo fmt --check

# Run clippy with workspace lints
lint:
    cargo clippy --all-targets --all-features --locked -- -D warnings

# Run clippy with pedantic lints (exploration only)
lint-pedantic:
    cargo clippy --all-targets --all-features -- -W clippy::pedantic

# Run all tests (excluding network-dependent)
test:
    cargo test --all-features --all-targets --locked

# Validate Rustdoc examples and doc warning cleanliness
docs-check:
    cargo test --doc --all-features --locked
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked

# Run end-to-end tests (requires network). Skips zero-assert stress demos (matches CI).
test-e2e:
    cargo test --all-features --all-targets --locked -- --ignored --skip stress_

# Run tests with coverage
coverage:
    cargo tarpaulin --out Html --output-dir coverage --all-features --timeout 120
    @echo "📊 Coverage report: coverage/index.html"

# Build release binary
build:
    cargo build --release --locked

# Run security audit
audit:
    cargo audit

# Run cargo-deny policy checks
deny:
    cargo deny check

# Run secret scanner
secrets:
    pre-commit run gitleaks --all-files

# Install pre-commit hooks
install-hooks:
    pre-commit install
    @echo "✅ Pre-commit hooks installed"

# Fix clippy warnings automatically (where possible)
fix:
    cargo clippy --fix --allow-dirty --allow-staged --all-targets --all-features

# Run full CI pipeline locally
ci: fmt-check lint docs-check test audit deny
    @echo "✅ CI pipeline passed!"

# Clean build artifacts
clean:
    cargo clean

# Show current cargo cache sizes (project target/ + global ~/.cargo)
cache-status:
    @echo "Project target/:"
    @du -sh target/ 2>/dev/null || echo "  (none)"
    @echo "Global ~/.cargo/registry/:"
    @du -sh ~/.cargo/registry/ 2>/dev/null || echo "  (none)"
    @echo "Global ~/.cargo/git/:"
    @du -sh ~/.cargo/git/ 2>/dev/null || echo "  (none)"

# Remove only incremental compilation cache (keeps compiled deps + binaries)
# Useful if CARGO_INCREMENTAL=1 was used for a session and bloated.
trim-incremental:
    rm -rf target/debug/incremental target/release/incremental
    @echo "Removed target/*/incremental"

# Check for outdated dependencies
outdated:
    cargo outdated
