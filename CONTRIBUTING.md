# Contributing to domain_status

## Prerequisites

- Rust 1.85+ ([install rustup](https://rustup.rs/))
- [just](https://github.com/casey/just): `cargo install just`
- (Optional) [pre-commit](https://pre-commit.com/): `pip install pre-commit`

## Quick Start

1. **Clone repository**
   ```bash
   git clone https://github.com/alexwoolford/domain_status.git
   cd domain_status
   ```

2. **Install pre-commit hooks** (recommended)
   ```bash
   just install-hooks
   ```

3. **Run checks before committing**
   ```bash
   just check   # Runs fmt + lint + test
   ```

## Development Workflow

### Running Checks

Use `just` for all operations:

```bash
just check        # Run all checks (fmt + lint + test)
just ci           # Run full CI pipeline locally
just fmt          # Format code
just lint         # Run clippy
just test         # Run tests
just coverage     # Generate coverage report
```

**Before creating a PR:**
```bash
just ci
```

### Code Quality Standards

1. **Formatting**: `cargo fmt` (enforced in CI)
2. **Linting**: `cargo clippy -- -D warnings` (enforced in CI)
3. **Testing**: All tests must pass
4. **Coverage**: Aim for >80%

### Clippy Lints

Workspace lints in `Cargo.toml` enforce:
- **Correctness**: Prevent numeric truncation, float comparison issues
- **Performance**: Detect needless clones, inefficient patterns
- **Maintainability**: Flag functions >100 lines, high complexity

### Pre-commit Hooks

Automatically run before each commit:
- **gitleaks**: Scan for secrets
- **File checks**: Whitespace, merge conflicts, etc.

Install: `just install-hooks`

## Common Issues

### Numeric Cast Warnings

**Problem:** `cast_possible_truncation` or `cast_precision_loss`

**Solution:**
```rust
// Bad
let count = items.len() as u32;

// Good
let count = u32::try_from(items.len())
    .expect("collection too large for u32");
```

### Float Comparison Warnings

**Problem:** `float_cmp` for direct equality

**Solution:**
```rust
// Bad
if ratio == 1.0 { }

// Good
const EPSILON: f64 = 1e-10;
if (ratio - 1.0).abs() < EPSILON { }
```

### Function Too Long

**Problem:** `too_many_lines` warning

**Solution:** Extract helper functions
```rust
// Extract logical blocks
fn process_item(item: &Item) -> Result<Output> {
    let data = extract_data(item)?;
    let validated = validate_data(data)?;
    transform_data(validated)
}
```

### Needless Clones

**Problem:** `needless_pass_by_value` or cloning in hot paths

**Solution:**
```rust
// Bad - clones unnecessarily
fn process(data: String) -> String {
    data.clone()
}

// Good - use references
fn process(data: &str) -> String {
    data.to_string()
}
```

## Pull Request Process

1. Create feature branch: `git checkout -b feature/your-feature`
2. Make changes and test: `just check`
3. Commit with clear messages (see below)
4. Push and create PR with description
5. Wait for CI (all checks must pass)
6. Address review feedback

### Commit Messages

Follow conventional commits:
```
<type>: <short description>

<optional body>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

Example:
```
feat: Add GeoIP caching

Implements LRU cache for GeoIP lookups to reduce API calls.

Closes #123
```

## Getting Help

- Questions? Open a GitHub Discussion
- Bug reports? Open an Issue
- Feature requests? Open an Issue with `[RFC]` prefix
