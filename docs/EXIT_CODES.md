# Exit Code Reference

## Exit Codes

| Code | Meaning | Triggered By |
|------|---------|--------------|
| 0 | Success | All URLs processed successfully, or failures ignored by policy (`--fail-on never`) |
| 1 | Configuration/Initialization Error | Invalid configuration, missing files, database initialization failure |
| 2 | Policy Failure Threshold Exceeded | Failures exceeded policy threshold (`--fail-on any-failure` or `--fail-on pct>N`) |
| 3 | Partial Success | PctGreaterThan mode with 0 URLs processed (scan incomplete) |

## Failure Policies (`--fail-on`)

### `never` (Default)
Always exits with code 0, regardless of failures.
- **Use Case**: CI/CD pipelines where you want to collect data even if some URLs fail
- **Behavior**: Logs failures but doesn't affect exit code

### `any-failure`
Exits with code 2 if ANY URL failed.
- **Use Case**: Strict monitoring where any failure is unacceptable
- **Behavior**: Single failure → exit 2

### `pct>` (Percentage Threshold)
Exits with code 2 if failure percentage exceeds threshold set by `--fail-on-pct-threshold`.
- **Use Case**: Allow acceptable failure rate (e.g., `--fail-on pct> --fail-on-pct-threshold 10`)
- **Behavior**: > 10% failures → exit 2, ≤ 10% → exit 0
- **Special**: 0 URLs processed → exit 3

### `errors-only`
Exits with code 2 only for critical errors (timeouts, DNS failures, certificate issues).
- **Use Case**: Distinguish between critical errors and expected failures (404s)
- **Note**: Currently behaves like `any-failure`

## Error Type Categories

The application tracks 23 distinct error types across these categories:

**HTTP Errors:** 400, 401, 403, 404, 429, 500, 502, 503, 504, redirect errors, generic HTTP errors

**DNS Errors:** NS lookup failures, TXT record failures, MX record failures

**TLS Errors:** Certificate validation failures

**Timeout Errors:** Request timeouts, processing timeouts

**Parsing Errors:** Title extraction failures, technology detection errors

## Examples

```bash
# Always succeed (for data collection)
domain_status scan urls.txt --fail-on never
echo $?  # Always 0

# Fail if any URL fails
domain_status scan urls.txt --fail-on any-failure
echo $?  # 0 if all success, 2 if any failure

# Fail if >5% failure rate
domain_status scan urls.txt --fail-on pct> --fail-on-pct-threshold 5
echo $?  # 0 if ≤5% failed, 2 if >5% failed, 3 if no URLs processed

# Configuration error
domain_status scan nonexistent.txt
echo $?  # 1 (file not found)
```
