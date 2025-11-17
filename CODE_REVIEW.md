# Code Review: Code Smells, Architecture & Performance Issues

## 🔴 Critical Issues

### 1. Blocking File I/O in Async Context
**Location**: `src/main.rs:67-68`
```rust
let file = File::open(&opt.file).context("Failed to open input file")?;
let reader = BufReader::new(file);
// ...
for line in reader.lines() {  // BLOCKING!
```

**Problem**: `BufReader::lines()` is a blocking iterator. This blocks the async runtime.

**Impact**: 
- Blocks the entire async runtime while reading file
- Prevents other tasks from running
- Poor performance for large files

**Fix**: Use `tokio::fs::File` and `tokio::io::AsyncBufReadExt::lines()`

---

### 2. HTML Parsed Twice
**Location**: 
- `src/http.rs:217` - `Html::parse_document(&body)`
- `src/tech_detection.rs:624` - `Html::parse_document(html)`

**Problem**: The same HTML is parsed twice - once for metadata extraction, once for tech detection.

**Impact**:
- 2x CPU overhead for HTML parsing
- 2x memory allocation
- Slower processing

**Fix**: Parse once, pass `Html` document to both functions (but `Html` is not `Send`, so need careful design)

---

### 3. TLS Connection Created Per-URL
**Location**: `src/tls.rs:86-101`
```rust
let sock = TcpStream::connect((domain.clone(), 443)).await?;
let mut tls_stream = connector.connect(server_name, sock).await?;
```

**Problem**: New TCP + TLS connection for every URL, even for same domain.

**Impact**:
- High latency (TLS handshake per URL)
- High CPU usage
- Connection overhead

**Fix**: Connection pooling or reuse (but complex due to SNI requirements)

---

## 🟡 Performance Issues

### 4. Excessive Cloning in Retry Logic
**Location**: `src/utils.rs:86-93`
```rust
let result = tokio_retry::Retry::spawn(retry_strategy, || {
    let client = client.clone();           // Arc clone (cheap)
    let redirect_client = redirect_client.clone();  // Arc clone (cheap)
    let url = url.clone();                 // String clone (expensive!)
    let pool = pool.clone();               // Arc clone (cheap)
    let extractor = extractor.clone();     // Arc clone (cheap)
    let error_stats = error_stats.clone(); // Arc clone (cheap)
    let resolver = resolver.clone();       // Arc clone (cheap)
```

**Problem**: `url.clone()` happens on every retry attempt. For exponential backoff with multiple retries, this adds up.

**Impact**: Unnecessary string allocations on retries

**Fix**: Move `url` outside retry closure, or use `Arc<String>`

---

### 5. String Allocations in Hot Path
**Location**: Multiple places
- `src/http.rs:152` - `response.url().to_string()`
- `src/http.rs:209` - `String::from_utf8_lossy(&bytes).to_string()`
- `src/http.rs:294` - `format!("_dmarc.{}", final_domain)`
- `src/utils.rs:116` - `anyhow::anyhow!("Non-retriable error: {}", e)`

**Problem**: Many unnecessary `String` allocations in hot path.

**Impact**: Memory churn, GC pressure (if applicable), slower execution

**Fix**: Use `&str` where possible, reuse buffers, use `Cow<str>`

---

### 6. HashMap Allocations in Tech Detection
**Location**: `src/tech_detection.rs:627, 640, 662, 679`
```rust
let mut meta_tags = HashMap::new();
let mut script_sources = Vec::new();
let mut cookies: HashMap<String, String> = ...;
let header_map: HashMap<String, String> = ...;
```

**Problem**: Multiple HashMap/Vec allocations per URL for tech detection.

**Impact**: Memory allocations, slower processing

**Fix**: Reuse buffers, use `with_capacity()` for known sizes

---

### 7. Inefficient Error String Matching
**Location**: `src/utils.rs:14-51`
```rust
fn is_retriable_error(error: &anyhow::Error) -> bool {
    let error_str = error.to_string().to_lowercase();  // Allocation!
    // ... string contains checks
}
```

**Problem**: Converts entire error to string and lowercases it just to check error type.

**Impact**: Unnecessary allocation and string processing

**Fix**: Use error chain inspection (`error.chain()`, `error.downcast_ref::<reqwest::Error>()`)

---

### 8. Unnecessary Header Cloning
**Location**: `src/http.rs:189`
```rust
let headers = response.headers().clone();
```

**Problem**: Clones entire HeaderMap when we only need to read from it.

**Impact**: Memory allocation

**Fix**: Use `&response.headers()` directly

---

## 🟠 Architectural Issues

### 9. Monolithic `handle_response` Function
**Location**: `src/http.rs:139-409` (270 lines!)

**Problem**: Function does too much:
- Domain extraction
- TLS certificate extraction
- DNS lookups (multiple)
- HTML parsing
- Technology detection
- Database insertion

**Impact**: 
- Hard to test
- Hard to maintain
- Hard to parallelize
- Violates single responsibility

**Fix**: Split into smaller functions:
- `extract_domain_info()`
- `extract_tls_info()`
- `extract_dns_info()`
- `extract_html_info()`
- `extract_tech_info()`
- `store_record()`

---

### 10. Synchronous File Reading
**Location**: `src/main.rs:67-133`
```rust
let file = File::open(&opt.file)?;
let reader = BufReader::new(file);
for line in reader.lines() {  // Blocking!
```

**Problem**: Blocks async runtime while reading file line-by-line.

**Impact**: Can't process URLs while reading file

**Fix**: Read file asynchronously or use `tokio::task::spawn_blocking`

---

### 11. No Early Exit for Non-HTML
**Location**: `src/http.rs:193-200`
```rust
// Enforce HTML content-type, else skip
if let Some(ct) = headers.get(reqwest::header::CONTENT_TYPE) {
    let ct = ct.to_str().unwrap_or("");
    if !ct.starts_with("text/html") {
        debug!("Skipping non-HTML content-type: {ct}");
        return Ok(());
    }
}
```

**Problem**: We check content-type AFTER:
- Resolving redirects
- Making HTTP request
- Getting response headers
- But BEFORE reading body (good!)

**Impact**: Still wastes time on redirect resolution and request for non-HTML

**Fix**: Check content-type earlier if possible (but redirects might change it)

---

### 12. Sequential DNS + TLS Operations
**Location**: `src/http.rs:164-185, 245-249`
```rust
// TLS extraction (sequential)
let (tls_version, ...) = if final_url.starts_with("https://") {
    match get_ssl_certificate_info(host.to_string()).await { ... }
}

// Then DNS (sequential)
let ip_address = resolve_host_to_ip(host, resolver).await?;
let reverse_dns_name = reverse_dns_lookup(&ip_address, resolver).await?;
```

**Problem**: TLS and DNS operations are independent but run sequentially.

**Impact**: Slower processing (adds latency)

**Fix**: Run in parallel with `tokio::join!`

---

### 13. Error Type Detection via String Matching
**Location**: `src/utils.rs:14-51`

**Problem**: Uses string matching to determine error type instead of proper error types.

**Impact**: Fragile, slow, error-prone

**Fix**: Use `anyhow::Error::chain()` and `downcast_ref` to inspect error types

---

## 🔵 Code Smells

### 14. Too Many Function Arguments
**Location**: `src/http.rs:139, 423`
- `handle_response`: 9 arguments
- `handle_http_request`: 8 arguments

**Problem**: Functions with many arguments are hard to use and maintain.

**Fix**: Group related arguments into structs:
```rust
struct RequestContext {
    client: Arc<reqwest::Client>,
    redirect_client: Arc<reqwest::Client>,
    pool: Arc<SqlitePool>,
    extractor: Arc<List>,
    resolver: Arc<TokioAsyncResolver>,
    error_stats: Arc<ErrorStats>,
}
```

---

### 15. Unnecessary Clones in Main Loop
**Location**: `src/main.rs:158-168`
```rust
let client_clone = Arc::clone(&client);
let redirect_client_clone = Arc::clone(&redirect_client);
let pool_clone = Arc::clone(&pool);
let extractor_clone = Arc::clone(&extractor);
let resolver_clone = Arc::clone(&resolver);
let completed_urls_clone = Arc::clone(&completed_urls);
let error_stats_clone = error_stats.clone();
```

**Problem**: Many individual clones. Could be grouped.

**Fix**: Create a context struct and clone once

---

### 16. Magic Numbers
**Location**: `src/tech_detection.rs:655`
```rust
.chars()
.take(50_000)  // Why 50KB?
```

**Problem**: Magic number without explanation

**Fix**: Extract to named constant with documentation

---

### 17. Unwrap in Error Path
**Location**: `src/http.rs:191`
```rust
let status_desc = status.canonical_reason().unwrap_or("Unknown Status Code");
```

**Problem**: `unwrap_or` is fine, but pattern is repeated

**Note**: This is acceptable, but could be more consistent

---

### 18. Inefficient JSON Serialization
**Location**: `src/http.rs:30-32`
```rust
fn serialize_json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string())
}
```

**Problem**: Creates new string on every call, even for same data

**Impact**: Minor, but adds up

**Fix**: Consider caching or using `Cow<str>`

---

## 📊 Summary

### Priority 1 (Critical - Fix Now)
1. ✅ Blocking file I/O in async context
2. ✅ HTML parsed twice
3. ✅ TLS connection per-URL

### Priority 2 (High - Fix Soon)
4. ✅ Excessive cloning in retry
5. ✅ String allocations in hot path
6. ✅ HashMap allocations
7. ✅ Inefficient error matching
8. ✅ Sequential DNS+TLS

### Priority 3 (Medium - Consider)
9. ✅ Monolithic functions
10. ✅ Too many function arguments
11. ✅ Magic numbers

### Priority 4 (Low - Nice to Have)
12. ✅ Unnecessary header cloning
13. ✅ JSON serialization efficiency

---

## Recommended Fix Order

1. **Fix blocking file I/O** - Biggest impact, easiest fix
2. **Fix HTML double-parsing** - High impact, medium complexity
3. **Parallelize DNS+TLS** - Medium impact, easy fix
4. **Fix error matching** - Medium impact, easy fix
5. **Reduce cloning** - Low impact, easy fix
6. **Refactor large functions** - Low impact, high complexity (do later)

