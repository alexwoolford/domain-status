# Performance Settings Analysis & Recommendations

## Executive Summary

Current settings appear conservative and may be suboptimal. Many values appear to be arbitrary defaults without empirical justification. This document analyzes each setting category and provides evidence-based recommendations, balancing performance with bot detection avoidance.

**Key Finding**: The system could likely run 2-5x faster with optimized settings, but bot detection risk increases significantly. The challenge is that many sites share bot detection infrastructure (Cloudflare, etc.), so requests cannot be treated in isolation.

---

## Current Settings Inventory

### 1. Concurrency Settings

| Setting | Current Value | Location |
|---------|--------------|----------|
| Max Concurrent Requests | 20 | `SEMAPHORE_LIMIT` / `--max-concurrency` |
| **Rationale**: "Lower default reduces bot detection risk" |

**Analysis**:
- **Too Conservative**: 20 concurrent requests is quite low for modern systems
- **Bot Detection Risk**: High concurrency (50-100+) can trigger rate limiting even with low RPS due to connection pattern detection
- **Recommendation**: 
  - **Conservative**: 30-40 (1.5-2x current)
  - **Moderate**: 50-75 (2.5-3.75x current)
  - **Aggressive**: 100-150 (5-7.5x current) - high bot detection risk
- **Key Insight**: Concurrency acts as a safety cap; rate limiting is the primary control mechanism

---

### 2. Rate Limiting Settings

| Setting | Current Value | Location |
|---------|--------------|----------|
| Initial RPS | 10 | `--rate-limit-rps` |
| Error Threshold | 20% | `--adaptive-error-threshold` (hidden) |
| Adjustment Interval | 5 seconds | Hardcoded in `limiter.rs` |
| Window Duration | 30 seconds | Hardcoded in `limiter.rs` |
| Window Size | 100 requests | Hardcoded in `limiter.rs` |
| Min RPS | 1 | Hardcoded in `limiter.rs` |
| Max RPS | Initial RPS (10) | Hardcoded in `limiter.rs` |
| Decrease Factor | 50% (0.5x) | Hardcoded in `limiter.rs` |
| Increase Factor | 10% (1.1x) | Hardcoded in `limiter.rs` |

**Analysis**:
- **Initial RPS (10)**: Very conservative. Most sites can handle 20-50 RPS from a single IP
- **Error Threshold (20%)**: Reasonable, but may be too sensitive for transient errors
- **Adjustment Interval (5s)**: Good - responsive but not jittery
- **Window Duration (30s)**: Reasonable for detecting patterns
- **Window Size (100)**: Good sample size
- **Max RPS Cap**: **Problem** - capped at initial RPS means system can never exceed 10 RPS even if conditions are perfect
- **Asymmetric Adjustment**: 50% decrease vs 10% increase creates slow recovery

**Recommendations**:
1. **Initial RPS**: 
   - **Conservative**: 15-20 RPS
   - **Moderate**: 25-35 RPS
   - **Aggressive**: 50-75 RPS (high bot detection risk)
2. **Max RPS Cap**: Allow 2-3x initial RPS (e.g., if initial=20, max=40-60)
3. **Increase Factor**: Increase to 15-20% for faster recovery
4. **Error Threshold**: Consider 25-30% to reduce false positives from transient errors
5. **Make settings configurable**: Window duration, adjustment interval, increase/decrease factors should be CLI flags

---

### 3. Retry Strategy

| Setting | Current Value | Location |
|---------|--------------|----------|
| Max Attempts | 3 (initial + 2 retries) | `RETRY_MAX_ATTEMPTS` |
| Initial Delay | 1000ms (1 second) | `RETRY_INITIAL_DELAY_MS` |
| Backoff Factor | 2x (doubles each retry) | `RETRY_FACTOR` |
| Max Delay | 20 seconds | `RETRY_MAX_DELAY_SECS` |

**Analysis**:
- **Max Attempts (3)**: Reasonable - prevents infinite retries
- **Initial Delay (1s)**: **Too Long** - adds 1-3 seconds of delay per retry
- **Backoff Factor (2x)**: Standard, but aggressive for fast recovery
- **Max Delay (20s)**: Reasonable cap

**Retry Timeline**:
- Attempt 1: Immediate
- Attempt 2: +1s delay (1s total)
- Attempt 3: +2s delay (3s total)
- **Total retry overhead**: Up to 3 seconds

**Recommendations**:
1. **Initial Delay**: Reduce to 250-500ms (4-8x faster)
   - Still provides backoff benefit
   - Reduces total retry overhead from 3s to ~0.75-1.5s
2. **Max Attempts**: Keep at 3 (good balance)
3. **Backoff Factor**: Keep at 2x (standard)
4. **Max Delay**: Reduce to 10-15s (faster recovery from transient issues)

**Performance Impact**: Reducing initial delay from 1s to 250ms could save 0.75-2.25 seconds per failed request, significantly improving throughput for error-prone sites.

---

### 4. Timeout Settings

| Setting | Current Value | Location |
|---------|--------------|----------|
| Per-URL Timeout | 45 seconds | `URL_PROCESSING_TIMEOUT` |
| HTTP Request Timeout | 10 seconds | `--timeout-seconds` |
| DNS Timeout | 10 seconds | `DNS_TIMEOUT_SECS` |
| TCP Connect Timeout | 5 seconds | `TCP_CONNECT_TIMEOUT_SECS` |
| TLS Handshake Timeout | 5 seconds | `TLS_HANDSHAKE_TIMEOUT_SECS` |

**Analysis**:
- **Per-URL Timeout (45s)**: Very generous - allows for slow sites but ties up resources
- **HTTP Timeout (10s)**: Reasonable for most sites
- **DNS Timeout (10s)**: Increased from 5s - may be too long
- **TCP/TLS Timeouts (5s)**: Reasonable

**Recommendations**:
1. **Per-URL Timeout**: Reduce to 30-35 seconds
   - Still generous for slow sites
   - Frees up resources faster
   - Formula: `HTTP timeout + DNS timeout + TCP timeout + TLS timeout + buffer = ~30s`
2. **HTTP Timeout**: Keep at 10s (good default)
3. **DNS Timeout**: Reduce to 5-7 seconds
   - Most DNS queries complete in <1s
   - 10s is excessive for most cases
4. **TCP/TLS Timeouts**: Keep at 5s (reasonable)

**Performance Impact**: Reducing per-URL timeout from 45s to 30s could improve throughput by 33% for slow sites, and reducing DNS timeout from 10s to 5s could save 5s per DNS failure.

---

### 5. Adaptive Rate Limiter - Hidden Settings

| Setting | Current Value | Location |
|---------|--------------|----------|
| Adjustment Interval | 5 seconds | Hardcoded in `limiter.rs:112` |
| Window Duration | 30 seconds | Hardcoded in `limiter.rs:48` |
| Window Size | 100 requests | Hardcoded in `limiter.rs:47` |
| Min Data Points | 10 requests | Hardcoded in `limiter.rs:124` |

**Analysis**:
- **Adjustment Interval (5s)**: Good - responsive but stable
- **Window Duration (30s)**: Reasonable for detecting patterns
- **Window Size (100)**: Good sample size
- **Min Data Points (10)**: Good - prevents premature adjustments

**Recommendations**:
1. **Make configurable**: These should be CLI flags for tuning
2. **Adjustment Interval**: Consider 3-5s range (faster response)
3. **Window Duration**: Consider 20-30s range (balance between responsiveness and stability)
4. **Window Size**: Keep at 100 (good sample size)

---

### 6. Batch Writing Settings

| Setting | Current Value | Location |
|---------|--------------|----------|
| Batch Size | 100 records | `BATCH_SIZE` |
| Flush Interval | 5 seconds | `BATCH_FLUSH_INTERVAL_SECS` |
| Channel Size Multiplier | 10x | `CHANNEL_SIZE_MULTIPLIER` |

**Analysis**:
- **Batch Size (100)**: Reasonable - balances memory vs. write efficiency
- **Flush Interval (5s)**: Good - prevents data loss while maintaining efficiency
- **Channel Size (1000)**: 10x batch size - provides good buffering

**Recommendations**:
- **No changes needed** - these settings are well-balanced

---

## Bot Detection Considerations

### Shared Infrastructure Problem

Many sites use shared bot detection infrastructure (Cloudflare, AWS WAF, etc.), which means:
- **Requests cannot be treated in isolation** - patterns across all requests matter
- **Connection patterns** are analyzed (bursts, timing, concurrency)
- **Rate limiting** is the primary defense, but concurrency also matters

### Bot Detection Triggers

1. **High Concurrency + Low RPS**: Suspicious pattern (many connections, few requests)
2. **Burst Patterns**: Sudden spikes in requests
3. **Consistent Timing**: Perfectly spaced requests (non-human)
4. **No User-Agent Rotation**: Same UA for all requests
5. **No Cookie/Session Handling**: Stateless requests

### Current Mitigations

✅ **Good**:
- Adaptive rate limiting (adjusts based on errors)
- User-Agent auto-update (Chrome version)
- Exponential backoff on retries
- Error rate monitoring

❌ **Missing**:
- Request timing jitter (adds randomness to request spacing)
- User-Agent rotation (currently single UA)
- Cookie/session handling (if needed)
- Per-domain rate limiting (different limits per domain)

---

## Recommended Optimizations

### Tier 1: Safe Optimizations (Low Bot Detection Risk)

1. **Reduce Retry Initial Delay**: 1000ms → 250-500ms
   - **Impact**: 0.75-2.25s saved per retry
   - **Risk**: Low - still provides backoff

2. **Reduce DNS Timeout**: 10s → 5-7s
   - **Impact**: 3-5s saved per DNS failure
   - **Risk**: Low - most DNS queries complete in <1s

3. **Reduce Per-URL Timeout**: 45s → 30-35s
   - **Impact**: 15s saved per slow request
   - **Risk**: Low - still generous timeout

4. **Increase Initial RPS**: 10 → 15-20 RPS
   - **Impact**: 50-100% throughput increase
   - **Risk**: Low-Medium - still conservative

5. **Remove Max RPS Cap**: Allow 2-3x initial RPS
   - **Impact**: System can adapt to good conditions
   - **Risk**: Low - adaptive system will reduce if needed

### Tier 2: Moderate Optimizations (Medium Bot Detection Risk)

1. **Increase Concurrency**: 20 → 30-50
   - **Impact**: 50-150% throughput increase
   - **Risk**: Medium - higher concurrency can trigger detection

2. **Increase Initial RPS**: 10 → 25-35 RPS
   - **Impact**: 150-250% throughput increase
   - **Risk**: Medium - may trigger rate limiting on some sites

3. **Faster Rate Limiter Recovery**: 10% → 15-20% increase
   - **Impact**: Faster recovery from transient errors
   - **Risk**: Medium - may overshoot and trigger errors

4. **Reduce Error Threshold**: 20% → 25-30%
   - **Impact**: Fewer false positives from transient errors
   - **Risk**: Medium - may miss real rate limiting

### Tier 3: Aggressive Optimizations (High Bot Detection Risk)

1. **High Concurrency**: 20 → 100-150
   - **Impact**: 400-650% throughput increase
   - **Risk**: High - likely to trigger bot detection

2. **High Initial RPS**: 10 → 50-75 RPS
   - **Impact**: 400-650% throughput increase
   - **Risk**: High - likely to trigger rate limiting

3. **Shorter Timeouts**: Reduce all timeouts by 30-50%
   - **Impact**: Faster failure detection, higher throughput
   - **Risk**: High - may fail on legitimate slow sites

---

## Implementation Recommendations

### 1. Make Hidden Settings Configurable

Add CLI flags for:
- `--adaptive-window-duration-secs` (default: 30)
- `--adaptive-adjustment-interval-secs` (default: 5)
- `--adaptive-increase-factor` (default: 0.1 = 10%)
- `--adaptive-decrease-factor` (default: 0.5 = 50%)
- `--adaptive-max-rps-multiplier` (default: 1.0, allow 2.0-3.0)
- `--adaptive-error-threshold` (already exists but hidden)

### 2. Add Request Timing Jitter

Add random delay (0-500ms) to request spacing to make patterns less detectable:
```rust
// Add jitter to rate limiter
let jitter = rand::random::<u64>() % 500; // 0-500ms
tokio::time::sleep(Duration::from_millis(jitter)).await;
```

### 3. Per-Domain Rate Limiting

Track rate limits per domain and apply different limits:
- Fast sites: Higher RPS
- Slow sites: Lower RPS
- Rate-limited sites: Very low RPS

### 4. Performance Monitoring

Add metrics to track:
- Actual throughput (requests/second)
- Error rates by type
- Retry success rates
- Timeout frequencies
- Rate limiter adjustments

Use these metrics to empirically determine optimal settings.

---

## Testing Strategy

### 1. Baseline Measurement

Run current settings on a representative sample and measure:
- Throughput (URLs/second)
- Error rates
- Retry rates
- Timeout rates
- Rate limiter adjustments

### 2. Incremental Optimization

Test each optimization independently:
1. Apply Tier 1 optimizations
2. Measure impact
3. If successful, apply Tier 2
4. Measure impact
5. If successful, consider Tier 3

### 3. Bot Detection Testing

Test on sites known to use bot detection:
- Cloudflare-protected sites
- AWS WAF-protected sites
- Custom bot detection

Monitor for:
- 429 errors
- 403 errors
- CAPTCHA challenges
- IP blocks

---

## Recommended Default Settings

### Conservative (Current + Safe Optimizations)

```rust
SEMAPHORE_LIMIT: 20 → 30
RATE_LIMIT_RPS: 10 → 15
RETRY_INITIAL_DELAY_MS: 1000 → 500
DNS_TIMEOUT_SECS: 10 → 7
URL_PROCESSING_TIMEOUT: 45s → 35s
ADAPTIVE_MAX_RPS_MULTIPLIER: 1.0 → 2.0
ADAPTIVE_INCREASE_FACTOR: 0.1 → 0.15
```

**Expected Impact**: 30-50% throughput increase, low bot detection risk

### Moderate (Balanced Performance/Risk)

```rust
SEMAPHORE_LIMIT: 20 → 50
RATE_LIMIT_RPS: 10 → 25
RETRY_INITIAL_DELAY_MS: 1000 → 250
DNS_TIMEOUT_SECS: 10 → 5
URL_PROCESSING_TIMEOUT: 45s → 30s
ADAPTIVE_MAX_RPS_MULTIPLIER: 1.0 → 2.5
ADAPTIVE_INCREASE_FACTOR: 0.1 → 0.2
ADAPTIVE_ERROR_THRESHOLD: 0.2 → 0.25
```

**Expected Impact**: 150-200% throughput increase, medium bot detection risk

### Aggressive (Maximum Performance)

```rust
SEMAPHORE_LIMIT: 20 → 100
RATE_LIMIT_RPS: 10 → 50
RETRY_INITIAL_DELAY_MS: 1000 → 250
DNS_TIMEOUT_SECS: 10 → 5
URL_PROCESSING_TIMEOUT: 45s → 25s
ADAPTIVE_MAX_RPS_MULTIPLIER: 1.0 → 3.0
ADAPTIVE_INCREASE_FACTOR: 0.1 → 0.25
ADAPTIVE_ERROR_THRESHOLD: 0.2 → 0.3
```

**Expected Impact**: 400-500% throughput increase, high bot detection risk

---

## Conclusion

Current settings are conservative and likely suboptimal. The system could run 2-5x faster with optimized settings, but bot detection risk increases. The key challenge is that many sites share bot detection infrastructure, so requests cannot be treated in isolation.

**Recommended Approach**:
1. Start with Tier 1 (Safe) optimizations
2. Measure impact and bot detection rates
3. Incrementally apply Tier 2 optimizations if Tier 1 is successful
4. Make hidden settings configurable for fine-tuning
5. Add performance monitoring to empirically determine optimal settings

**Key Insight**: The adaptive rate limiter is well-designed but limited by conservative initial settings and caps. Removing the max RPS cap and increasing initial RPS could provide significant gains with minimal bot detection risk.

