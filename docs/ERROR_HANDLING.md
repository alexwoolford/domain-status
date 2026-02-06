# Error Handling Guide

## Error Type Overview

The application uses three complementary error handling approaches:

### 1. Typed Errors (thiserror)

Used for **initialization, configuration, and database** operations where distinct error types provide value:

- `InitializationError` - Logger, HTTP client, DNS resolver setup failures
- `DatabaseError` - SQLite connection and query failures
- `ConfigValidationError` - Configuration validation with field-level details

**When to use:** Errors that require type-specific handling or recovery

### 2. Contextual Errors (anyhow)

Used for **processing and fetch** operations where error context is more valuable than type:

- HTTP requests (fetch module)
- Technology fingerprinting (fingerprint module)
- Data parsing (parse module)

**When to use:** Complex operations where error context chain provides debugging value

### 3. Wrapper Errors (FailureContextError)

Used to **attach additional context** to errors while preserving the error chain:

- HTTP request/response headers
- Redirect chains
- Request timing information

**When to use:** Need to preserve structured debugging information

## Error Categorization

The `error_handling` module provides sophisticated error categorization:

- 32 distinct `ErrorType` variants (HTTP 4xx/5xx, DNS, TLS, timeouts)
- 3 `WarningType` variants (missing optional metadata)
- 4 `InfoType` variants (redirects, bot detection)

This categorization drives exit code policy evaluation and error statistics.

## Best Practices

### Writing Error Messages

✅ **Good** - Actionable and specific:
```rust
Err(anyhow::anyhow!(
    "Ruleset not initialized. Call init_ruleset() before running detection."
))
```

❌ **Bad** - Generic and unhelpful:
```rust
Err(anyhow::anyhow!("Ruleset not initialized"))
```

### Adding Context

✅ **Good** - Use `.context()` for operation description:
```rust
serde_json::from_str(&json_text)
    .context("Failed to parse categories JSON")?
```

❌ **Bad** - Raw errors without context:
```rust
serde_json::from_str(&json_text)?
```

### Panic Safety

✅ **Good** - Validate at compile/startup time:
```rust
static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"pattern")
        .expect("PATTERN is a hardcoded valid regex")
});
```

❌ **Bad** - Runtime panic on static data:
```rust
fn get_pattern() -> Regex {
    Regex::new(r"pattern").unwrap()
}
```

## Testing Error Paths

All error paths should be tested:

```rust
#[test]
fn test_config_validation_max_concurrency_zero() {
    let config = Config {
        max_concurrency: 0,
        ..Default::default()
    };
    let err = config.validate().unwrap_err();
    assert_eq!(err.field, "max_concurrency");
    assert!(err.message.contains("greater than 0"));
}
```

## Panic Safety Guarantee

The application is designed to never panic during normal operation:

- All regex patterns validated at program startup
- Division operations guarded against divide-by-zero
- Mutex operations use safe recovery strategies
- Proper error handling throughout with actionable messages

See [tests/panic_safety.rs](../tests/panic_safety.rs) for comprehensive panic safety tests.

## Exit Codes

See [EXIT_CODES.md](EXIT_CODES.md) for detailed exit code reference and policy-based failure handling.
