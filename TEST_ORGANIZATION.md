# Test Organization Guide

## Current Structure

Your codebase uses a **hybrid approach** that's actually quite common in Rust:

1. **Separate test files** (using `include!()`):
   - `src/domain/tests.rs` → included in `domain/mod.rs`
   - `src/dns/tests.rs` → included in `dns/mod.rs`
   - `src/parse/tests.rs` → included in `parse/mod.rs`
   - `src/fetch/tests.rs` → included in `fetch/mod.rs`
   - `src/utils/tests.rs` → included in `utils/mod.rs`

2. **Inline tests** (using `#[cfg(test)] mod tests { ... }`):
   - `src/error_handling/mod.rs`
   - `src/security/mod.rs`
   - `src/storage/circuit_breaker.rs`
   - `src/fingerprint/mod.rs`
   - `src/app/url.rs`

3. **Integration tests**:
   - `tests/integration_test.rs` (at project root)

## Rust Best Practices

### Official Recommendation
- **Unit tests**: Inline in the same file with `#[cfg(test)] mod tests { ... }`
- **Integration tests**: Separate files in `tests/` directory

### When to Use Each Approach

#### Use Inline Tests (`#[cfg(test)] mod tests`) When:
- ✅ Test suite is small (< 100 lines)
- ✅ Tests are closely tied to the implementation
- ✅ You want tests immediately visible when reading the code
- ✅ Module is simple and self-contained

**Example**: `src/security/mod.rs` (small, focused tests)

#### Use Separate Test Files (`include!("tests.rs")`) When:
- ✅ Test suite is large (> 100 lines)
- ✅ Tests would clutter the main module file
- ✅ You want to keep implementation code clean and focused
- ✅ Module has many test cases

**Example**: `src/domain/tests.rs` (many domain extraction test cases)

## Recommended Structure for This Project

### Keep Current Pattern, But Make It Consistent

**Guideline**: Use separate test files when tests exceed ~80-100 lines.

### Module-by-Module Decision

| Module | Current | Recommendation | Reason |
|--------|---------|----------------|--------|
| `domain` | Separate | ✅ Keep separate | Large test suite |
| `dns` | Separate | ✅ Keep separate | Large test suite |
| `parse` | Separate | ✅ Keep separate | Large test suite |
| `fetch` | Separate | ✅ Keep separate | Large test suite |
| `utils` | Separate | ✅ Keep separate | Multiple utility functions |
| `error_handling` | Inline | ✅ Keep inline | Small, focused tests |
| `security` | Inline | ✅ Keep inline | Small, focused tests |
| `circuit_breaker` | Inline | ✅ Keep inline | Small, focused tests |
| `fingerprint` | Inline | ⚠️ Consider separate | Growing test suite |
| `app/url` | Inline | ✅ Keep inline | Small, focused tests |

### New Modules

For new test files, follow this pattern:

**Small test suite (< 80 lines)**:
```rust
// src/my_module.rs
pub fn my_function() { ... }

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_my_function() { ... }
}
```

**Large test suite (> 80 lines)**:
```rust
// src/my_module/mod.rs
pub fn my_function() { ... }

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
```

```rust
// src/my_module/tests.rs
use super::*;

#[test]
fn test_my_function() { ... }
// ... many more tests
```

## Integration Tests

Keep integration tests in `tests/` directory:
- `tests/integration_test.rs` - HTTP client tests with mock server
- Future: `tests/database_test.rs` - Database operations with in-memory SQLite

## Test Naming Conventions

- Test files: `tests.rs` (lowercase, plural)
- Test functions: `test_<function_name>` or `test_<scenario>`
- Test modules: `tests` (lowercase, plural)

## Benefits of Current Approach

1. **Clean separation**: Implementation code stays focused
2. **Easy navigation**: Tests are easy to find (either inline or in `tests.rs`)
3. **Flexibility**: Can choose based on test suite size
4. **Rust-idiomatic**: Both patterns are valid and commonly used

## Consistency Recommendations

1. **Document the pattern**: Add a comment in modules explaining why tests are separate/inline
2. **Be consistent within a module**: Don't mix inline and separate tests in the same module
3. **Review periodically**: If inline tests grow > 100 lines, consider moving to separate file

## Example: Adding Tests to a New Module

### Scenario: Adding tests to `src/fingerprint/patterns.rs`

Since `patterns.rs` is a submodule, we have two options:

**Option 1: Inline (if tests are small)**
```rust
// src/fingerprint/patterns.rs
pub(crate) fn matches_pattern(...) { ... }

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_matches_pattern() { ... }
}
```

**Option 2: Separate file (if tests are large)**
```rust
// src/fingerprint/patterns.rs
pub(crate) fn matches_pattern(...) { ... }

#[cfg(test)]
mod tests {
    include!("patterns/tests.rs");
}
```

```rust
// src/fingerprint/patterns/tests.rs
use super::*;

#[test]
fn test_matches_pattern() { ... }
```

**Recommendation**: For `patterns.rs`, use **Option 1 (inline)** initially. If tests grow beyond ~80 lines, refactor to Option 2.

## Summary

Your current test organization is **clean and intuitive**. The hybrid approach (separate files for large suites, inline for small ones) is a valid Rust pattern that many projects use.

**Key principles**:
- ✅ Keep tests close to the code they test
- ✅ Use separate files when tests would clutter the main file
- ✅ Keep integration tests in `tests/` directory
- ✅ Be consistent within each module
- ✅ Document the pattern choice if it's non-obvious

