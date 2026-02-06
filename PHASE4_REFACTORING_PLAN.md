# Phase 4 Refactoring Plan: Code Complexity Reduction

## Status: READY FOR IMPLEMENTATION

**Note:** Phases 1-3 are complete. This document provides detailed guidance for future Phase 4 work.

## Overview

Phase 4 addresses code maintainability by refactoring large functions. The primary target is `src/lib.rs:169` - the `run_scan` function with 445 lines and 54/25 complexity (2x the threshold).

## Priority: `run_scan` Function Refactoring

**File:** `src/lib.rs:169-715`
**Current State:** 445 lines, cognitive complexity 54/25
**Target:** <150 lines per function, complexity <25

### Analysis

The function has three distinct phases that can be cleanly separated:

1. **Initialization Phase (lines 180-371, ~190 lines)**
   - Config validation
   - File reading setup (stdin vs file)
   - Client initialization (HTTP, redirect, DNS resolver)
   - Database setup and migrations
   - Rate limiter configuration (static + adaptive)
   - Fingerprint ruleset loading
   - GeoIP initialization
   - Context creation

2. **URL Processing Loop (lines 376-583, ~210 lines)**
   - URL reading from input
   - Validation and normalization
   - Semaphore acquisition
   - Task spawning with retry logic
   - Progress tracking
   - Adaptive rate limit recording
   - Error handling and failure recording

3. **Completion Phase (lines 585-715, ~130 lines)**
   - Task result collection
   - Logging task management
   - Statistics calculation
   - Database finalization (WAL checkpoint, pool closure)
   - Report generation

### Refactoring Strategy

#### Step 1: Define Data Structures

```rust
/// Context for URL scanning containing all initialized resources
struct ScanContext {
    // Network resources
    client: Arc<reqwest::Client>,
    redirect_client: Arc<reqwest::Client>,
    extractor: Arc<psl::List>,
    resolver: Arc<hickory_resolver::TokioResolver>,

    // Database
    pool: Arc<sqlx::SqlitePool>,

    // Rate limiting
    semaphore: Arc<tokio::sync::Semaphore>,
    request_limiter: Option<Arc<governor::RateLimiter<...>>>,
    rate_limiter_shutdown: Option<tokio::task::JoinHandle<()>>,
    adaptive_limiter: Option<Arc<AdaptiveRateLimiter>>,

    // Fingerprints & GeoIP
    ruleset: crate::fingerprint::models::FingerprintRuleset,
    geoip_metadata: Option<crate::geoip::GeoIpMetadata>,

    // State tracking
    error_stats: Arc<ProcessingStats>,
    timing_stats: Arc<TimingStats>,
    completed_urls: Arc<AtomicUsize>,
    failed_urls: Arc<AtomicUsize>,
    total_urls_attempted: Arc<AtomicUsize>,
    total_urls_in_file: Arc<AtomicUsize>,

    // Metadata
    run_id: String,
    start_time: std::time::Instant,
    start_time_arc: Arc<std::time::Instant>,

    // Processing context
    processing_ctx: Arc<ProcessingContext>,
}

/// Input source for URL reading
enum UrlSource {
    File {
        lines: tokio::io::Lines<BufReader<tokio::fs::File>>,
        total_lines: usize,
    },
    Stdin {
        lines: tokio::io::Lines<BufReader<tokio::io::Stdin>>,
    },
}
```

#### Step 2: Extract Initialization Function

```rust
/// Initializes all resources needed for URL scanning.
///
/// This function sets up network clients, database connections, rate limiters,
/// fingerprint rulesets, and GeoIP data. It returns a ScanContext containing
/// all initialized resources.
///
/// # Errors
///
/// Returns an error if any initialization step fails (database, clients, etc.)
async fn init_scan_context(
    config: &mut Config,
) -> Result<ScanContext> {
    // Config validation
    config.validate()
        .context("Configuration validation failed")?;

    // User agent setup
    if config.user_agent == DEFAULT_USER_AGENT {
        config.user_agent = crate::user_agent::get_default_user_agent(None).await;
    }

    // Database initialization
    let pool = init_db_pool_with_path(&config.db_path)
        .await
        .context("Failed to initialize database pool")?;
    crate::storage::run_migrations(&pool)
        .await
        .context("Failed to run database migrations")?;

    // Client initialization
    let client = init_client(config).await?;
    let redirect_client = init_redirect_client(config).await?;
    let extractor = init_extractor();
    let resolver = init_resolver()?;

    // Rate limiter initialization
    let semaphore = init_semaphore(config.max_concurrency);
    let (request_limiter, rate_limiter_shutdown) =
        init_rate_limiter_pair(config.rate_limit_rps, config.max_concurrency);
    let adaptive_limiter = init_adaptive_limiter(
        config.rate_limit_rps,
        config.adaptive_error_threshold,
        request_limiter.as_ref(),
    );

    // Fingerprint & GeoIP initialization
    let ruleset = crate::fingerprint::init_ruleset(
        config.fingerprints.as_deref(),
        None,
    ).await?;
    let geoip_metadata = crate::geoip::init_geoip(
        config.geoip.as_deref(),
        None,
    ).await.ok();

    // Create run metadata
    let start_time = std::time::Instant::now();
    let start_time_epoch = Utc::now().timestamp_millis();
    let run_id = format!("run_{}", start_time_epoch);

    insert_run_metadata(
        &pool,
        &run_id,
        start_time_epoch,
        env!("CARGO_PKG_VERSION"),
        Some(&ruleset.metadata.source),
        Some(&ruleset.metadata.version),
        geoip_metadata.as_ref().map(|m| m.version.as_str()),
    ).await?;

    // Initialize state tracking
    let error_stats = Arc::new(ProcessingStats::new());
    let timing_stats = Arc::new(TimingStats::new());
    let completed_urls = Arc::new(AtomicUsize::new(0));
    let failed_urls = Arc::new(AtomicUsize::new(0));
    let total_urls_attempted = Arc::new(AtomicUsize::new(0));

    // Create processing context
    let db_circuit_breaker = Arc::new(
        crate::storage::circuit_breaker::DbWriteCircuitBreaker::new()
    );
    let processing_ctx = Arc::new(ProcessingContext::new(
        Arc::clone(&client),
        Arc::clone(&redirect_client),
        Arc::clone(&extractor),
        Arc::clone(&resolver),
        error_stats.clone(),
        Some(run_id.clone()),
        config.enable_whois,
        Arc::clone(&db_circuit_breaker),
        Arc::clone(&pool),
        Arc::clone(&timing_stats),
    ));

    Ok(ScanContext {
        client,
        redirect_client,
        extractor,
        resolver,
        pool,
        semaphore,
        request_limiter,
        rate_limiter_shutdown,
        adaptive_limiter,
        ruleset,
        geoip_metadata,
        error_stats,
        timing_stats,
        completed_urls,
        failed_urls,
        total_urls_attempted,
        total_urls_in_file: Arc::new(AtomicUsize::new(0)), // Set later
        run_id,
        start_time,
        start_time_arc: Arc::new(start_time),
        processing_ctx,
    })
}
```

#### Step 3: Extract URL Source Setup

```rust
/// Opens the URL input source (file or stdin) and counts total lines.
///
/// # Returns
///
/// Returns a tuple of (UrlSource, total_line_count)
async fn open_url_source(
    config: &Config,
) -> Result<(UrlSource, usize)> {
    if config.file.as_os_str() == "-" {
        info!("Reading URLs from stdin");
        let stdin_lines = BufReader::new(tokio::io::stdin()).lines();
        Ok((UrlSource::Stdin { lines: stdin_lines }, 0))
    } else {
        // Count lines first
        let file_for_counting = tokio::fs::File::open(&config.file)
            .await
            .context("Failed to open input file for line counting")?;
        let reader = BufReader::new(file_for_counting);
        let mut count = 0usize;
        let mut counting_lines = reader.lines();
        while let Ok(Some(line)) = counting_lines.next_line().await {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                count += 1;
            }
        }
        info!("Total URLs in file: {}", count);

        // Re-open file for reading
        let file = tokio::fs::File::open(&config.file)
            .await
            .context("Failed to open input file")?;
        let file_lines = BufReader::new(file).lines();

        Ok((UrlSource::File { lines: file_lines, total_lines: count }, count))
    }
}
```

#### Step 4: Extract Task Spawning Logic

```rust
/// Spawns a task to process a single URL.
///
/// Handles semaphore acquisition, rate limiting, retries, and result tracking.
fn spawn_url_processing_task(
    url: String,
    ctx: Arc<ProcessingContext>,
    permit: tokio::sync::OwnedSemaphorePermit,
    request_limiter: Option<Arc<governor::RateLimiter<...>>>,
    adaptive_limiter: Option<Arc<AdaptiveRateLimiter>>,
    completed_urls: Arc<AtomicUsize>,
    failed_urls: Arc<AtomicUsize>,
    progress_callback: Option<Arc<dyn Fn(usize, usize, usize) + Send + Sync>>,
    total_urls: usize,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _permit = permit;

        if let Some(ref limiter) = request_limiter {
            limiter.acquire().await;
        }

        let process_start = std::time::Instant::now();
        let url_arc = Arc::from(url.as_str());

        let result = tokio::time::timeout(
            URL_PROCESSING_TIMEOUT,
            crate::utils::process_url(Arc::clone(&url_arc), ctx.clone()),
        ).await;

        match result {
            Ok(ProcessUrlResult { result: Ok(()), .. }) => {
                handle_url_success(
                    &completed_urls,
                    &failed_urls,
                    &progress_callback,
                    total_urls,
                    &adaptive_limiter,
                ).await;
            }
            Ok(ProcessUrlResult { result: Err(e), retry_count }) => {
                handle_url_failure(
                    &url_arc,
                    e,
                    retry_count,
                    process_start.elapsed().as_secs_f64(),
                    &ctx,
                    &completed_urls,
                    &failed_urls,
                    &progress_callback,
                    total_urls,
                    &adaptive_limiter,
                ).await;
            }
            Err(_) => {
                handle_url_timeout(
                    &url_arc,
                    process_start.elapsed().as_secs_f64(),
                    &ctx,
                    &completed_urls,
                    &failed_urls,
                    &progress_callback,
                    total_urls,
                    &adaptive_limiter,
                ).await;
            }
        }
    })
}
```

#### Step 5: Extract Result Handling

```rust
/// Handles successful URL processing.
async fn handle_url_success(
    completed_urls: &Arc<AtomicUsize>,
    failed_urls: &Arc<AtomicUsize>,
    progress_callback: &Option<Arc<dyn Fn(usize, usize, usize) + Send + Sync>>,
    total_urls: usize,
    adaptive_limiter: &Option<Arc<AdaptiveRateLimiter>>,
) {
    completed_urls.fetch_add(1, Ordering::SeqCst);
    invoke_progress_callback(progress_callback, completed_urls, failed_urls, total_urls);
    if let Some(adaptive) = adaptive_limiter {
        adaptive.record_success().await;
    }
}

/// Handles failed URL processing.
async fn handle_url_failure(
    url: &Arc<str>,
    error: anyhow::Error,
    retry_count: u32,
    elapsed: f64,
    ctx: &Arc<ProcessingContext>,
    completed_urls: &Arc<AtomicUsize>,
    failed_urls: &Arc<AtomicUsize>,
    progress_callback: &Option<Arc<dyn Fn(usize, usize, usize) + Send + Sync>>,
    total_urls: usize,
    adaptive_limiter: &Option<Arc<AdaptiveRateLimiter>>,
) {
    failed_urls.fetch_add(1, Ordering::SeqCst);
    invoke_progress_callback(progress_callback, completed_urls, failed_urls, total_urls);
    log::warn!("Failed to process URL {}: {}", url, error);

    let context = crate::storage::failure::extract_failure_context(&error);
    if let Err(record_err) = record_url_failure(
        crate::storage::failure::FailureRecordParams {
            pool: &ctx.db.pool,
            extractor: &ctx.network.extractor,
            url: url.as_ref(),
            error: &error,
            context,
            retry_count,
            elapsed_time: elapsed,
            run_id: ctx.config.run_id.as_deref(),
            circuit_breaker: Arc::clone(&ctx.db.circuit_breaker),
        }
    ).await {
        log::warn!("Failed to record failure for {}: {}", url, record_err);
    }

    if let Some(adaptive) = adaptive_limiter {
        let is_429 = error.chain().any(|cause| {
            cause.downcast_ref::<reqwest::Error>()
                .and_then(|e| e.status())
                .map(|s| s.as_u16() == 429)
                .unwrap_or(false)
        });
        if is_429 {
            adaptive.record_rate_limited().await;
        }
    }
}

/// Handles timeout during URL processing.
async fn handle_url_timeout(
    url: &Arc<str>,
    elapsed: f64,
    ctx: &Arc<ProcessingContext>,
    completed_urls: &Arc<AtomicUsize>,
    failed_urls: &Arc<AtomicUsize>,
    progress_callback: &Option<Arc<dyn Fn(usize, usize, usize) + Send + Sync>>,
    total_urls: usize,
    adaptive_limiter: &Option<Arc<AdaptiveRateLimiter>>,
) {
    failed_urls.fetch_add(1, Ordering::SeqCst);
    invoke_progress_callback(progress_callback, completed_urls, failed_urls, total_urls);
    log::warn!("Timeout processing URL {}", url);

    let timeout_error = anyhow::anyhow!(
        "Process URL timeout after {} seconds for {}",
        URL_PROCESSING_TIMEOUT.as_secs(),
        url
    );

    let context = crate::storage::failure::FailureContext {
        final_url: None,
        redirect_chain: Vec::new(),
        response_headers: Vec::new(),
        request_headers: Vec::new(),
    };

    #[allow(clippy::cast_possible_truncation)]
    if let Err(record_err) = record_url_failure(
        crate::storage::failure::FailureRecordParams {
            pool: &ctx.db.pool,
            extractor: &ctx.network.extractor,
            url: url.as_ref(),
            error: &timeout_error,
            context,
            retry_count: RETRY_MAX_ATTEMPTS as u32 - 1,
            elapsed_time: elapsed,
            run_id: ctx.config.run_id.as_deref(),
            circuit_breaker: Arc::clone(&ctx.db.circuit_breaker),
        }
    ).await {
        log::warn!("Failed to record timeout failure for {}: {}", url, record_err);
    }

    ctx.config.error_stats.increment_error(ErrorType::ProcessUrlTimeout);
    if let Some(adaptive) = adaptive_limiter {
        adaptive.record_timeout().await;
    }
}
```

#### Step 6: Simplified Main Function

```rust
pub async fn run_scan(mut config: Config) -> Result<ScanReport> {
    // Phase 1: Initialize all resources
    let mut ctx = init_scan_context(&mut config).await?;

    // Phase 2: Open URL source
    let (mut url_source, total_lines) = open_url_source(&config).await?;
    ctx.total_urls_in_file.store(total_lines, Ordering::SeqCst);

    // Start status server if configured
    if let Some(port) = config.status_port {
        spawn_status_server(port, &ctx);
    }

    // Phase 3: Process URLs
    let tasks = process_urls(
        &mut url_source,
        &ctx,
        &config.progress_callback,
        total_lines,
    ).await?;

    // Phase 4: Collect results and finalize
    finalize_scan(
        tasks,
        ctx,
        &config,
        total_lines,
    ).await
}
```

### Implementation Checklist

- [ ] Define `ScanContext` struct
- [ ] Define `UrlSource` enum
- [ ] Extract `init_scan_context()` function
- [ ] Extract `open_url_source()` function
- [ ] Extract `spawn_url_processing_task()` function
- [ ] Extract `handle_url_success()` function
- [ ] Extract `handle_url_failure()` function
- [ ] Extract `handle_url_timeout()` function
- [ ] Extract `process_urls()` function
- [ ] Extract `finalize_scan()` function
- [ ] Update `run_scan()` to use extracted functions
- [ ] Run all tests (`cargo test --lib --all-features`)
- [ ] Run clippy (`cargo clippy -- -D warnings`)
- [ ] Verify no behavior changes (integration tests)
- [ ] Update complexity suppressions
- [ ] Commit changes

### Testing Strategy

1. **Unit Tests:** Verify each extracted function independently
2. **Integration Tests:** Run existing `test_run_scan_*` tests
3. **E2E Test:** Process url-list.txt and verify database contents
4. **Performance:** Benchmark before/after to ensure no regression

### Estimated Effort

- Planning & design: 2-3 hours
- Implementation: 8-12 hours
- Testing & debugging: 4-6 hours
- Documentation: 1-2 hours

**Total:** 15-23 hours of focused work

### Benefits

- **Maintainability:** Functions <150 lines, complexity <25
- **Testability:** Each phase can be tested independently
- **Readability:** Clear separation of concerns
- **Debuggability:** Easier to identify which phase fails

### Risks & Mitigation

**Risk:** Breaking existing functionality
**Mitigation:** Comprehensive test suite (1,357 tests), incremental changes, test after each extraction

**Risk:** Performance regression
**Mitigation:** Benchmark critical path, avoid unnecessary allocations

**Risk:** Scope creep
**Mitigation:** Focus only on `run_scan` function, defer other functions

## Other Large Functions

After completing `run_scan`, consider refactoring these functions in priority order:

1. `src/export/jsonl.rs:42` - 396 lines, 31/25 complexity
2. `src/export/csv.rs:35` - 346 lines, 29/25 complexity
3. `src/fetch/response/html.rs:25` - 159 lines, 29/25 complexity
4. `src/fingerprint/ruleset/github/directory.rs:13` - 176 lines

Use similar extraction patterns as outlined above.

## Conclusion

This refactoring plan provides a clear, step-by-step approach to reducing the complexity of the `run_scan` function. The work is ready to begin whenever prioritized.
