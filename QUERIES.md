# SQLite Query Examples

This document provides common SQL queries for analyzing `domain_status` scan results.

## Basic Queries

### 1. List all scanned URLs with status codes

```sql
SELECT
    final_url,
    http_status,
    final_domain,
    timestamp
FROM url_records
ORDER BY timestamp DESC;
```

### 2. Find all failed URLs

```sql
SELECT
    final_url,
    http_status,
    error_message,
    timestamp
FROM url_records
WHERE http_status >= 400 OR http_status IS NULL
ORDER BY timestamp DESC;
```

### 3. Find all redirects

```sql
SELECT
    ur.final_url,
    ur.http_status,
    ur.final_domain,
    COUNT(rd.id) as redirect_count
FROM url_records ur
LEFT JOIN redirects rd ON ur.id = rd.url_record_id
WHERE ur.http_status BETWEEN 300 AND 399
   OR rd.id IS NOT NULL
GROUP BY ur.id
ORDER BY redirect_count DESC;
```

### 4. View redirect chains

```sql
SELECT
    ur.final_url as final_url,
    rd.redirect_url,
    rd.redirect_status,
    rd.redirect_sequence
FROM url_records ur
JOIN redirects rd ON ur.id = rd.url_record_id
ORDER BY ur.id, rd.redirect_sequence;
```

## Technology Detection

### 5. Find all detected technologies

```sql
SELECT
    ur.final_url,
    ur.final_domain,
    t.name as technology,
    t.category,
    t.version
FROM url_records ur
JOIN technologies t ON ur.id = t.url_record_id
ORDER BY ur.final_domain, t.category, t.name;
```

### 6. Count technologies by category

```sql
SELECT
    t.category,
    COUNT(DISTINCT t.name) as technology_count,
    COUNT(DISTINCT ur.final_domain) as domain_count
FROM technologies t
JOIN url_records ur ON t.url_record_id = ur.id
GROUP BY t.category
ORDER BY technology_count DESC;
```

### 7. Find domains using specific technology

```sql
SELECT DISTINCT
    ur.final_domain,
    ur.final_url
FROM url_records ur
JOIN technologies t ON ur.id = t.url_record_id
WHERE t.name = 'nginx'  -- Replace with your technology
ORDER BY ur.final_domain;
```

## TLS Certificate Analysis

### 8. Find certificates expiring soon (within 30 days)

```sql
SELECT
    ur.final_url,
    ur.final_domain,
    tls.not_after,
    julianday(tls.not_after) - julianday('now') as days_until_expiry
FROM url_records ur
JOIN certificates tls ON ur.id = tls.url_record_id
WHERE julianday(tls.not_after) - julianday('now') BETWEEN 0 AND 30
ORDER BY days_until_expiry ASC;
```

### 9. Find all expired certificates

```sql
SELECT
    ur.final_url,
    ur.final_domain,
    tls.not_after,
    julianday('now') - julianday(tls.not_after) as days_expired
FROM url_records ur
JOIN certificates tls ON ur.id = tls.url_record_id
WHERE julianday(tls.not_after) < julianday('now')
ORDER BY days_expired DESC;
```

### 10. List certificate issuers

```sql
SELECT
    tls.issuer,
    COUNT(DISTINCT ur.final_domain) as domain_count
FROM certificates tls
JOIN url_records ur ON tls.url_record_id = ur.id
GROUP BY tls.issuer
ORDER BY domain_count DESC;
```

## DNS Analysis

### 11. Find all DNS records for a domain

```sql
SELECT
    ur.final_domain,
    dns.record_type,
    dns.record_value
FROM url_records ur
JOIN dns_records dns ON ur.id = dns.url_record_id
WHERE ur.final_domain = 'example.com'  -- Replace with your domain
ORDER BY dns.record_type;
```

### 12. Find domains with SPF records

```sql
SELECT DISTINCT
    ur.final_domain,
    dns.record_value as spf_record
FROM url_records ur
JOIN dns_records dns ON ur.id = dns.url_record_id
WHERE dns.record_type = 'TXT'
  AND dns.record_value LIKE 'v=spf1%'
ORDER BY ur.final_domain;
```

### 13. Find domains with DMARC records

```sql
SELECT DISTINCT
    ur.final_domain,
    dns.record_value as dmarc_record
FROM url_records ur
JOIN dns_records dns ON ur.id = dns.url_record_id
WHERE dns.record_type = 'TXT'
  AND (dns.record_value LIKE 'v=DMARC1%' OR dns.record_value LIKE '_dmarc.%')
ORDER BY ur.final_domain;
```

## GeoIP Analysis

### 14. Find all domains by country

```sql
SELECT
    ur.final_domain,
    ur.final_url,
    geo.country_code,
    geo.country_name,
    geo.city
FROM url_records ur
JOIN geoip geo ON ur.id = geo.url_record_id
ORDER BY geo.country_code, geo.city;
```

### 15. Count domains by country

```sql
SELECT
    geo.country_code,
    geo.country_name,
    COUNT(DISTINCT ur.final_domain) as domain_count
FROM url_records ur
JOIN geoip geo ON ur.id = geo.url_record_id
GROUP BY geo.country_code, geo.country_name
ORDER BY domain_count DESC;
```

## Run History

### 16. List all scan runs

```sql
SELECT
    run_id,
    timestamp,
    version,
    fingerprints_source,
    fingerprints_version,
    geoip_version
FROM runs
ORDER BY timestamp DESC;
```

### 17. Compare results between runs

```sql
-- Find URLs that changed status between runs
SELECT
    ur1.final_url,
    ur1.http_status as status_run1,
    ur2.http_status as status_run2,
    ur1.timestamp as timestamp_run1,
    ur2.timestamp as timestamp_run2
FROM url_records ur1
JOIN url_records ur2 ON ur1.final_domain = ur2.final_domain
WHERE ur1.run_id = 'run_1234567890'  -- Replace with your run IDs
  AND ur2.run_id = 'run_1234567891'
  AND ur1.http_status != ur2.http_status;
```

### 18. Find new technologies detected in latest run

```sql
-- Compare technologies between two runs
SELECT DISTINCT
    t2.name as new_technology,
    t2.category,
    ur2.final_domain
FROM technologies t2
JOIN url_records ur2 ON t2.url_record_id = ur2.id
WHERE ur2.run_id = (SELECT run_id FROM runs ORDER BY timestamp DESC LIMIT 1)
  AND NOT EXISTS (
    SELECT 1
    FROM technologies t1
    JOIN url_records ur1 ON t1.url_record_id = ur1.id
    WHERE ur1.run_id = (SELECT run_id FROM runs ORDER BY timestamp DESC LIMIT 1 OFFSET 1)
      AND t1.name = t2.name
      AND ur1.final_domain = ur2.final_domain
  )
ORDER BY ur2.final_domain, t2.category;
```

## Error Analysis

### 19. Find all errors by type

```sql
SELECT
    error_type,
    COUNT(*) as error_count,
    COUNT(DISTINCT domain) as affected_domains
FROM url_failures
GROUP BY error_type
ORDER BY error_count DESC;
```

### 20. Find domains with most failures

```sql
SELECT
    domain,
    COUNT(*) as failure_count,
    GROUP_CONCAT(DISTINCT error_type) as error_types
FROM url_failures
GROUP BY domain
ORDER BY failure_count DESC
LIMIT 20;
```

## Performance Analysis

### 21. Find slowest URLs (by response time)

```sql
SELECT
    final_url,
    final_domain,
    http_elapsed_ms,
    timestamp
FROM url_records
WHERE http_elapsed_ms IS NOT NULL
ORDER BY http_elapsed_ms DESC
LIMIT 20;
```

### 22. Average response time by domain

```sql
SELECT
    final_domain,
    AVG(http_elapsed_ms) as avg_response_ms,
    MIN(http_elapsed_ms) as min_response_ms,
    MAX(http_elapsed_ms) as max_response_ms,
    COUNT(*) as request_count
FROM url_records
WHERE http_elapsed_ms IS NOT NULL
GROUP BY final_domain
ORDER BY avg_response_ms DESC;
```

## Security Analysis

### 23. Find domains without HTTPS

```sql
SELECT
    final_url,
    final_domain,
    http_status
FROM url_records
WHERE final_url LIKE 'http://%'
ORDER BY final_domain;
```

### 24. Find domains with security warnings

```sql
SELECT
    ur.final_url,
    ur.final_domain,
    sw.warning_type,
    sw.warning_message
FROM url_records ur
JOIN security_warnings sw ON ur.id = sw.url_record_id
ORDER BY ur.final_domain, sw.warning_type;
```

## Advanced Queries

### 25. Complete domain summary

```sql
SELECT
    ur.final_domain,
    COUNT(DISTINCT ur.id) as url_count,
    MIN(ur.http_status) as min_status,
    MAX(ur.http_status) as max_status,
    AVG(ur.http_elapsed_ms) as avg_response_ms,
    COUNT(DISTINCT t.name) as technology_count,
    GROUP_CONCAT(DISTINCT t.category) as technology_categories
FROM url_records ur
LEFT JOIN technologies t ON ur.id = t.url_record_id
GROUP BY ur.final_domain
ORDER BY url_count DESC;
```

### 26. Find domains with multiple redirects

```sql
SELECT
    ur.final_domain,
    ur.final_url,
    COUNT(rd.id) as redirect_count,
    GROUP_CONCAT(rd.redirect_url, ' -> ') as redirect_chain
FROM url_records ur
JOIN redirects rd ON ur.id = rd.url_record_id
GROUP BY ur.id
HAVING redirect_count > 3
ORDER BY redirect_count DESC;
```

## Tips

- Use `julianday('now')` for date calculations in SQLite
- The `run_id` field links records to specific scan runs
- `timestamp` is stored as milliseconds since epoch
- Use `GROUP_CONCAT()` to aggregate multiple values into a single column
- Join with `runs` table to filter by scan version or date

## Exporting Results

To export query results to CSV:

```bash
sqlite3 domain_status.db <<EOF
.headers on
.mode csv
.output results.csv
SELECT * FROM url_records WHERE http_status = 200;
EOF
```

Or use the `--fail-on` flag and export subcommand (when implemented):

```bash
domain_status export --db domain_status.db --format csv --query "SELECT * FROM url_records"
```
