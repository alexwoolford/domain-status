# Developer task runner for domain_status
# Install: cargo install just
# Run: just <command>

# Default recipe shows available commands
default:
    @just --list

# Run all checks (formatting, linting, tests)
check: fmt lint test
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

# Run end-to-end tests (requires network)
test-e2e:
    cargo test --all-features --all-targets --locked -- --ignored

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
ci: fmt-check lint test audit
    @echo "✅ CI pipeline passed!"

# Clean build artifacts
clean:
    cargo clean

# Check for outdated dependencies
outdated:
    cargo outdated
