# Production Hardening Guide

This guide documents operational best practices, scalability limits, and recommended configurations for running `domain_status` in production environments.

## Table of Contents

- [Critical Configuration](#critical-configuration)
- [Database Management](#database-management)
- [Concurrency and Connection Pooling](#concurrency-and-connection-pooling)
- [Cache Management](#cache-management)
- [Resource Limits](#resource-limits)
- [Monitoring and Alerting](#monitoring-and-alerting)
- [Scalability Limits](#scalability-limits)

---

## Critical Configuration

### Security Defaults (Implemented in v0.1.9+)

The following security limits are now enforced by default:

| Limit | Value | Purpose | Config Constant |
|-------|-------|---------|----------------|
| **HTTP Header Count** | 100 | Prevent header bomb attacks | `MAX_HEADER_COUNT` |
| **TXT Record Size** | 1024 bytes | Prevent DNS tunneling attacks | `MAX_TXT_RECORD_SIZE` |
| **Response Body Size** | 2 MB | Prevent compression bombs | `MAX_RESPONSE_BODY_SIZE` |
| **Redirect Hops** | 10 | Prevent redirect loops | `MAX_REDIRECT_HOPS` |

**Impact**: Malicious sites sending excessive headers (>100) or oversized TXT records (>1KB) will have data truncated with warnings logged.

---

## Database Management

### Retention Policy

**Problem**: Database grows unbounded without retention policy.

**At Scale**:
- 100K URLs/day × 365 days = 36.5M URLs/year
- 36.5M URLs × 15 rows/URL ≈ 550M database rows
- Estimated size: 50-80GB after 1 year

#### Recommended Retention Policy

**Default: 30 days** (suitable for most deployments)

```bash
# Manual cleanup (run periodically via cron)
sqlite3 domain_status.db <<EOF
-- Delete runs older than 30 days
DELETE FROM runs WHERE start_time_ms < (strftime('%s', 'now', '-30 days') * 1000);
-- Runs table has ON DELETE CASCADE, so related records are auto-deleted
VACUUM;
EOF
```

**Production Script** (`cleanup_old_runs.sh`):

```bash
#!/bin/bash
# Cleanup database runs older than retention period
# Usage: ./cleanup_old_runs.sh [database_path] [retention_days]

DB_PATH="${1:-./domain_status.db}"
RETENTION_DAYS="${2:-30}"

echo "Cleaning up runs older than ${RETENTION_DAYS} days from ${DB_PATH}"

# Count rows before cleanup
BEFORE=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM urls;")

# Delete old runs (cascade deletes related records)
sqlite3 "$DB_PATH" <<EOF
DELETE FROM runs
WHERE start_time_ms < (strftime('%s', 'now', '-${RETENTION_DAYS} days') * 1000);
EOF

# Count rows after cleanup
AFTER=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM urls;")
DELETED=$((BEFORE - AFTER))

echo "Deleted ${DELETED} URL records"
echo "Database size before VACUUM:"
ls -lh "$DB_PATH" | awk '{print $5}'

# Reclaim disk space
sqlite3 "$DB_PATH" "VACUUM;"

echo "Database size after VACUUM:"
ls -lh "$DB_PATH" | awk '{print $5}'
```

**Cron Schedule** (daily cleanup at 2 AM):

```cron
0 2 * * * /path/to/cleanup_old_runs.sh /path/to/domain_status.db 30 >> /var/log/domain_status_cleanup.log 2>&1
```

#### Retention Policy by Deployment Size

| Deployment Size | Daily Scans | Recommended Retention | Expected DB Size |
|-----------------|-------------|----------------------|------------------|
| Small | <10K URLs/day | 60 days | 5-10 GB |
| Medium | 10K-100K URLs/day | 30 days | 10-30 GB |
| Large | 100K-1M URLs/day | 14 days | 20-50 GB |
| Enterprise | >1M URLs/day | 7 days | 30-80 GB |

### WAL Mode and Checkpointing

**Current Configuration**: WAL mode is enabled by default (`init_db_pool_with_path()`).

**Recommended**: Add periodic checkpointing to prevent unbounded WAL growth.

```bash
# Manual WAL checkpoint (returns disk space to main database file)
sqlite3 domain_status.db "PRAGMA wal_checkpoint(TRUNCATE);"
```

**Add to cleanup script**:

```bash
# After VACUUM, checkpoint WAL
sqlite3 "$DB_PATH" "PRAGMA wal_checkpoint(TRUNCATE);"
```

### Database Optimization

**Analyze statistics** (improve query performance):

```bash
# Run after significant data changes or monthly
sqlite3 domain_status.db "ANALYZE;"
```

---

## Concurrency and Connection Pooling

### Critical Mismatch Issue

**Problem**: Database connection pool size (30) << max concurrency (500).

**Current Configuration** (`src/storage/pool.rs:62`):
- `max_connections = 30`
- Default `max_concurrency = 30` (CLI default)
- Max allowed `max_concurrency = 500` (CLI flag)

#### Behavior at Different Concurrency Levels

| Concurrency | Pool Size | Behavior | Recommendation |
|------------|-----------|----------|----------------|
| 30 | 30 | **Optimal** | Default, no contention |
| 50 | 30 | **Acceptable** | 20 workers may experience delays (1-2s) |
| 100 | 30 | **Degraded** | 70 workers block, 30-50% timeout rate |
| 200+ | 30 | **Critical** | Throughput collapse, >80% timeout rate |

#### Recommendations

**Option 1: Match pool size to concurrency** (Best performance, higher resource usage)

```rust
// src/storage/pool.rs
let pool = SqlitePoolOptions::new()
    .max_connections(max_concurrency) // Match user's --max-concurrent flag
    .acquire_timeout(Duration::from_secs(5))
    .idle_timeout(Some(Duration::from_secs(60)))
    .connect_with(options)
    .await?;
```

**Trade-offs**:
- ✅ No worker blocking
- ✅ Maximum throughput
- ❌ Higher memory usage (~1MB per connection)
- ❌ More file descriptors (SQLite opens multiple files per connection)

**Option 2: Document effective concurrency limit** (Current approach)

Keep pool size at 30, document that effective concurrency is capped:

```bash
# README.md warning
Note: Effective maximum concurrency is limited by database connection pool size (30).
Setting --max-concurrent > 30 may result in increased timeouts and reduced throughput.
For high-concurrency workloads (>30), consider batching or write queuing.
```

**Option 3: Implement write queue** (Future enhancement)

Decouple workers from database connections using async channel:

```rust
// Pseudo-code
let (tx, rx) = mpsc::channel(1000); // 1000-entry write queue

// Workers send to channel (non-blocking)
tx.send(url_record).await?;

// Single writer task drains queue
tokio::spawn(async move {
    while let Some(record) = rx.recv().await {
        insert_url_record(&pool, record).await?;
    }
});
```

**Immediate Action**: Add CLI validation:

```rust
// src/cli.rs or wherever max_concurrent is parsed
if max_concurrent > 30 {
    eprintln!("WARNING: --max-concurrent {} exceeds database pool size (30).", max_concurrent);
    eprintln!("This may cause increased timeouts and reduced throughput.");
    eprintln!("For high concurrency, consider batching requests or multiple runs.");
}
```

---

## Cache Management

### WHOIS Cache

**Location**: `~/.cache/domain_status/whois/` (or `$XDG_CACHE_HOME`)

**Current Behavior**:
- 7-day TTL per domain
- Lazy cleanup (only on access)
- **No quota limit**

**Growth Rate**:

| Daily Scans | 7-Day Cache Size | 30-Day Cache Size | 1-Year (no cleanup) |
|-------------|------------------|-------------------|---------------------|
| 10K domains | 350 MB | 1.5 GB | 18 GB |
| 100K domains | 3.5 GB | 15 GB | 180 GB |
| 1M domains | 35 GB | 150 GB | 1.8 TB |

#### Recommended WHOIS Cache Management

**Option 1: Manual cleanup** (immediate)

```bash
# Delete WHOIS cache older than 7 days
find ~/.cache/domain_status/whois/ -name "*.json" -mtime +7 -delete

# Add to cron (daily at 3 AM)
0 3 * * * find ~/.cache/domain_status/whois/ -name "*.json" -mtime +7 -delete
```

**Option 2: Disk quota monitoring** (recommended)

```bash
# Check WHOIS cache size
du -sh ~/.cache/domain_status/whois/

# Alert if >10GB
CACHE_SIZE_MB=$(du -sm ~/.cache/domain_status/whois/ | awk '{print $1}')
if [ "$CACHE_SIZE_MB" -gt 10240 ]; then
    echo "WARNING: WHOIS cache exceeds 10GB ($CACHE_SIZE_MB MB)"
fi
```

### Fingerprint Cache

**Location**: `~/.cache/domain_status/fingerprints/`

**Size**: ~10MB (static rulesets)

**TTL**: 7 days

**Recommendation**: No action needed, size is bounded.

### GeoIP Cache

**Location**: `~/.cache/domain_status/geoip/`

**Size**: ~100MB (MaxMind databases)

**TTL**: 7 days

**Recommendation**: No action needed, size is bounded.

---

## Resource Limits

### Memory

**Per Worker**:
- HTTP connection: ~100 KB
- Response body (max): 2 MB
- TLS handshake: ~50 KB
- **Total per worker**: ~2.2 MB

**Total Memory** (at max concurrency):
- 30 workers: ~66 MB (base)
- 100 workers: ~220 MB
- 500 workers: ~1.1 GB

**Recommendation**: Allocate 2x calculated memory for safety margin.

### Disk Space

**Database**:
- Small (< 100K URLs): 1-5 GB
- Medium (100K-1M URLs): 5-30 GB
- Large (> 1M URLs): 30-100 GB

**Caches** (WHOIS + Fingerprints + GeoIP):
- Small deployment: 500 MB - 2 GB
- Medium deployment: 2-10 GB
- Large deployment: 10-50 GB

**Total Disk Recommendation**:
- Small: 10 GB free
- Medium: 50 GB free
- Large: 150 GB free

### File Descriptors

**SQLite connections**: Each connection opens 3-5 file descriptors.

**Calculation**:
- Pool size 30 = ~120 file descriptors
- Pool size 100 = ~400 file descriptors

**System Limit Check**:

```bash
ulimit -n  # Should be >1024 for production
```

**Increase limit** (if needed):

```bash
# /etc/security/limits.conf
* soft nofile 4096
* hard nofile 8192
```

---

## Monitoring and Alerting

### Key Metrics

| Metric | Warning Threshold | Critical Threshold | Action |
|--------|------------------|-------------------|--------|
| Database size | 50% of disk | 80% of disk | Run retention cleanup |
| WHOIS cache size | 10 GB | 20 GB | Manual cleanup or quota |
| Worker timeout rate | 5% | 10% | Reduce concurrency |
| Circuit breaker open | N/A | Any occurrence | Investigate database |
| Memory usage | 70% of available | 90% of available | Reduce concurrency |

### Logging

**Warning-level events to monitor**:

```bash
# Header bomb detection
grep "has.*headers (limit:" domain_status.log

# TXT record truncation (DNS tunneling)
grep "TXT record.*truncating" domain_status.log

# Database write failures (may trigger circuit breaker)
grep "Failed to insert" domain_status.log

# WHOIS timeouts
grep "WHOIS.*timed out" domain_status.log
```

### Health Checks

**Database health**:

```bash
# Check WAL size (should be <100MB)
ls -lh domain_status.db-wal

# Check row count vs retention policy
sqlite3 domain_status.db "SELECT
    MIN(start_time_ms / 1000) as oldest_unix_timestamp,
    datetime(MIN(start_time_ms / 1000), 'unixepoch') as oldest_run,
    COUNT(*) as total_runs
FROM runs;"
```

**Cache health**:

```bash
# WHOIS cache file count
find ~/.cache/domain_status/whois/ -name "*.json" | wc -l

# Oldest cached WHOIS file
find ~/.cache/domain_status/whois/ -name "*.json" -printf '%T+ %p\n' | sort | head -1
```

---

## Scalability Limits

### Known Limits (as of v0.1.9)

| Limit | Value | Behavior Beyond Limit |
|-------|-------|----------------------|
| **Max effective concurrency** | 30 | Workers block on DB connections (5s timeout) |
| **Database recommended size** | <100 GB | Query performance degrades, index page faults |
| **WHOIS cache (no quota)** | Unbounded | Can fill disk; requires manual monitoring |
| **Single-run performance** | ~100K URLs | Beyond this, consider batching into multiple runs |

### Scaling Strategies

**Horizontal Scaling** (multiple instances):

```bash
# Split URL list into chunks
split -l 10000 urls.txt chunk_

# Run multiple instances
for chunk in chunk_*; do
    domain_status scan --input-file "$chunk" \
        --database "db_$(basename $chunk).db" &
done
wait
```

**Temporal Batching** (spread load over time):

```bash
# Process 10K URLs every hour
0 * * * * domain_status scan --input-file daily_batch.txt --max-concurrent 30
```

**Read Replica** (for queries):

SQLite supports multiple readers. Create read-only copy for analysis:

```bash
cp domain_status.db domain_status_readonly.db
sqlite3 domain_status_readonly.db "PRAGMA query_only = ON;"
```

---

## Summary of Immediate Actions

1. **Set up retention policy cron job** (30-day default)
2. **Monitor WHOIS cache size** (alert if >10GB)
3. **Add CLI warning** for `--max-concurrent > 30`
4. **Schedule periodic VACUUM** (weekly or after cleanup)
5. **Set up log monitoring** for attack patterns
6. **Document disk space requirements** based on expected load

---

## Contact and Support

For questions or issues related to production deployments:
- GitHub Issues: https://github.com/alexwoolford/domain_status/issues
- Documentation: https://github.com/alexwoolford/domain_status/tree/main/docs

Last Updated: 2025-02-11
Version: 0.1.9+
