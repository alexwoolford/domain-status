# Error Handling Policy

## Overview

This document establishes the error handling policy for the `domain_status` codebase. Consistent error handling improves code maintainability, debugging efficiency, and user experience.

## Guiding Principles

1. **Fail Fast for Critical Errors**: Configuration errors, database connection failures, and schema issues should propagate immediately and stop execution
2. **Graceful Degradation for Recoverable Errors**: Individual URL failures, DNS timeouts, and TLS handshake errors should be logged but allow processing to continue
3. **Consistent Error Messages**: Use structured, parseable error messages that include context
4. **User-Friendly Output**: CLI errors should be actionable and clear; detailed errors go to logs

## Error Categories

### 1. Critical Errors (Propagate with `?` or `return Err`)

These errors indicate fundamental issues that prevent the application from functioning correctly. They should **stop execution immediately**.

**Examples:**
- Database connection failures
- Configuration parsing errors
- Database schema migration failures
- File I/O errors (reading config files, creating database)
- Missing required configuration (e.g., invalid paths)

**Pattern:**
```rust
pub fn init_database(path: &Path) -> Result<DbPool, DatabaseError> {
    let pool = SqlitePool::connect(&format!("sqlite:{}", path.display()))
        .await
        .map_err(|e| {
            error!("Failed to connect to database at {}: {}", path.display(), e);
            DatabaseError::SqlError(e)
        })?;  // Propagate error immediately

    Ok(pool)
}
```

**Log Level:** `log::error!`

### 2. Recoverable Errors (Log and Continue)

These errors occur during normal operation when processing individual items. The application should log them and continue processing remaining items.

**Examples:**
- Individual URL fetch failures (DNS resolution, connection timeout, HTTP errors)
- TLS handshake failures for specific domains
- Invalid HTML parsing for a single page
- Technology detection failures
- WHOIS lookup timeouts
- GeoIP lookup failures for individual IPs

**Pattern:**
```rust
pub async fn fetch_url(url: &str) -> Option<Response> {
    match client.get(url).send().await {
        Ok(response) => Some(response),
        Err(e) => {
            log::warn!("Failed to fetch {}: {}", url, e);
            // Record failure in database for tracking
            record_failure(url, &e).await;
            None  // Return None and let caller continue
        }
    }
}
```

**Log Level:** `log::warn!`

### 3. Informational Messages (Log Only)

These are expected events that don't indicate errors but are useful for monitoring and debugging.

**Examples:**
- Rate limit adjustments (adaptive rate limiter)
- Cache operations (hits, misses, evictions)
- Progress updates
- Configuration loaded successfully
- Graceful shutdown initiated

**Pattern:**
```rust
pub fn adjust_rate_limit(&mut self, new_rate: f64) {
    log::info!("Adjusting rate limit from {:.1} to {:.1} RPS based on error rate",
        self.current_rate, new_rate);
    self.current_rate = new_rate;
}
```

**Log Level:** `log::info!` or `log::debug!`

## Error Message Format Standards

### Format Template

Use consistent, structured error messages:

```
Context: {what_operation} - Error: {error_details}
```

**Examples:**

**Good:**
```rust
log::error!("Failed to connect to database at {}: {}", db_path.display(), error);
log::warn!("Failed to fetch URL {}: {}", url, error);
log::warn!("Failed to batch insert {} security headers for url_status_id {}: {}",
    count, url_status_id, error);
```

**Avoid:**
```rust
log::error!("Error: {}", error);  // Too vague
log::warn!("Something went wrong");  // No context
log::error!("Database error");  // No details
```

### Include Relevant Context

Error messages should include:
- **What was being attempted** (e.g., "Failed to fetch URL", "Failed to insert record")
- **Relevant identifiers** (URL, domain, database ID, file path)
- **The actual error** (from the error object)

### Multi-Item Operations

For batch operations, include counts:

```rust
log::warn!("Failed to batch insert {} nameservers for url_status_id {}: {}",
    nameservers.len(), url_status_id, error);
```

## Error Handling by Component

### Database Layer (`src/storage/`)

**Critical Operations** (propagate errors):
- Connection pool initialization
- Schema migrations
- Main record insertion (url_status table)

**Recoverable Operations** (log and continue):
- Satellite table insertions (headers, DNS records, technologies)
- Enrichment data insertion (GeoIP, WHOIS)

**Rationale:** If the main URL record cannot be inserted, data integrity is compromised. However, if enrichment data fails, the URL scan is still valuable.

### HTTP Fetching (`src/fetch/`)

**All fetch operations are recoverable:**
- Network errors (DNS, connection, timeout)
- HTTP errors (4xx, 5xx)
- Response parsing errors

**Pattern:** Log warning, record failure details in database, return None/Error to caller

### Fingerprint Detection (`src/fingerprint/`)

**All detection errors are recoverable:**
- Pattern matching failures
- Invalid regex patterns in rulesets
- HTML parsing issues

**Pattern:** Log warning, continue with remaining detection patterns

### Rate Limiting (`src/adaptive_rate_limiter/`)

**Informational only:**
- Rate adjustments based on error rates
- Token acquisition/release

**Pattern:** Use `log::info!` for rate changes, `log::debug!` for token operations

## Testing Error Handling

When writing tests for error scenarios:

1. **Test Critical Errors:** Verify that critical errors propagate correctly
2. **Test Graceful Degradation:** Verify that recoverable errors are logged but don't stop processing
3. **Test Error Messages:** Verify error messages include expected context

**Example:**
```rust
#[tokio::test]
async fn test_insert_with_database_error() {
    // Simulate database connection failure
    let result = insert_record(&invalid_pool, &data).await;

    assert!(result.is_err());  // Should propagate error
    assert!(matches!(result.unwrap_err(), DatabaseError::SqlError(_)));
}

#[tokio::test]
async fn test_fetch_with_network_error() {
    // Simulate network timeout
    let result = fetch_url("http://invalid.domain.test").await;

    assert!(result.is_none());  // Should return None, not panic
    // Verify warning was logged (if using log capture)
}
```

## Migration Guide

When updating existing error handling to match this policy:

1. **Identify Error Category:** Is it Critical, Recoverable, or Informational?
2. **Apply Correct Pattern:** Propagate, log-and-continue, or info-only
3. **Update Error Messages:** Follow the format template
4. **Test:** Ensure error handling behavior matches expectations
5. **Don't Change Behavior:** Only standardize the format, not when errors are propagated vs. logged

## Examples in Practice

### Example 1: Database Connection (Critical)

```rust
pub async fn init_db_pool_with_path(db_path: &Path) -> Result<DbPool, DatabaseError> {
    // Create database file if it doesn't exist
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&db_path)
    {
        Ok(_) => info!("Database file created successfully."),
        Err(ref e) if e.kind() == ErrorKind::AlreadyExists => {
            info!("Database file already exists.")
        }
        Err(e) => {
            error!("Failed to create database file at {}: {}", db_path.display(), e);
            return Err(DatabaseError::FileCreationError(e.to_string()));
        }
    }

    // Connection errors propagate
    let pool = SqlitePool::connect(&format!("sqlite:{}", db_path.display()))
        .await
        .map_err(|e| {
            error!("Failed to connect to database: {}", e);
            DatabaseError::SqlError(e)
        })?;

    Ok(Arc::new(pool))
}
```

### Example 2: URL Fetch (Recoverable)

```rust
pub async fn fetch_url_with_retries(
    client: &Client,
    url: &str,
    max_retries: u32,
) -> Option<FetchResult> {
    for attempt in 1..=max_retries {
        match client.get(url).send().await {
            Ok(response) => return Some(extract_data(response).await),
            Err(e) => {
                if attempt < max_retries {
                    log::warn!("Failed to fetch {} (attempt {}/{}): {} - Retrying...",
                        url, attempt, max_retries, e);
                    tokio::time::sleep(Duration::from_secs(2_u64.pow(attempt))).await;
                } else {
                    log::warn!("Failed to fetch {} after {} attempts: {}",
                        url, max_retries, e);
                    return None;
                }
            }
        }
    }
    None
}
```

### Example 3: Rate Limit Adjustment (Informational)

```rust
pub fn adjust_rate_based_on_errors(&mut self, error_rate: f64) {
    if error_rate > 0.20 {
        let new_rate = self.current_rate * 0.5;
        log::info!(
            "High error rate ({:.1}%) detected - Reducing rate from {:.1} to {:.1} RPS",
            error_rate * 100.0,
            self.current_rate,
            new_rate
        );
        self.current_rate = new_rate;
    } else if error_rate < 0.10 && self.current_rate < self.max_rate {
        let new_rate = (self.current_rate * 1.15).min(self.max_rate);
        log::info!(
            "Low error rate ({:.1}%) detected - Increasing rate from {:.1} to {:.1} RPS",
            error_rate * 100.0,
            self.current_rate,
            new_rate
        );
        self.current_rate = new_rate;
    }
}
```

## Summary

**Critical Errors:** Propagate immediately with `?` or `return Err`, log with `log::error!`
**Recoverable Errors:** Log with `log::warn!` and continue processing, return None/default value
**Informational:** Log with `log::info!` or `log::debug!`

**Message Format:** `"Context: {operation} - Error: {details}"`

This policy ensures consistent, predictable error handling across the codebase while maintaining the robust functionality that makes `domain_status` production-ready.
