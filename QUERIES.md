# SQLite Query Examples

This document provides common SQL queries for analyzing `domain_status` scan results.

## Basic Queries

### 1. List all scanned URLs with status codes

```sql
SELECT
    domain,
    status,
    final_domain,
    timestamp
FROM url_status
ORDER BY timestamp DESC;
```

### 2. Find all failed URLs

```sql
SELECT
    domain,
    status,
    status_description,
    timestamp
FROM url_status
WHERE status >= 400 OR status = 0
ORDER BY timestamp DESC;
```

### 3. Find all redirects

```sql
SELECT
    us.domain,
    us.final_domain,
    us.status,
    COUNT(urc.id) as redirect_count
FROM url_status us
LEFT JOIN url_redirect_chain urc ON us.id = urc.url_status_id
WHERE us.status BETWEEN 300 AND 399
   OR urc.id IS NOT NULL
GROUP BY us.id
ORDER BY redirect_count DESC;
```

### 4. View redirect chains

```sql
SELECT
    us.final_domain,
    urc.url as redirect_url,
    urc.sequence_order
FROM url_status us
JOIN url_redirect_chain urc ON us.id = urc.url_status_id
ORDER BY us.id, urc.sequence_order;
```

## Technology Detection

### 5. Find all detected technologies

```sql
SELECT
    us.domain,
    us.final_domain,
    ut.technology_name,
    ut.technology_category
FROM url_status us
JOIN url_technologies ut ON us.id = ut.url_status_id
ORDER BY us.final_domain, ut.technology_category, ut.technology_name;
```

### 6. Count technologies by category

```sql
SELECT
    ut.technology_category,
    COUNT(DISTINCT ut.technology_name) as technology_count,
    COUNT(DISTINCT us.final_domain) as domain_count
FROM url_technologies ut
JOIN url_status us ON ut.url_status_id = us.id
GROUP BY ut.technology_category
ORDER BY technology_count DESC;
```

### 7. Find domains using specific technology

```sql
SELECT DISTINCT
    us.final_domain,
    us.domain
FROM url_status us
JOIN url_technologies ut ON us.id = ut.url_status_id
WHERE ut.technology_name = 'nginx'  -- Replace with your technology
ORDER BY us.final_domain;
```

## TLS Certificate Analysis

### 8. Find certificates expiring soon (within 30 days)

```sql
SELECT
    us.domain,
    us.final_domain,
    datetime(us.ssl_cert_valid_to/1000, 'unixepoch') as cert_expiry,
    (us.ssl_cert_valid_to - strftime('%s', 'now') * 1000) / (1000 * 60 * 60 * 24.0) as days_until_expiry
FROM url_status us
WHERE us.ssl_cert_valid_to IS NOT NULL
  AND (us.ssl_cert_valid_to - strftime('%s', 'now') * 1000) / (1000 * 60 * 60 * 24.0) BETWEEN 0 AND 30
ORDER BY days_until_expiry ASC;
```

### 9. Find all expired certificates

```sql
SELECT
    us.domain,
    us.final_domain,
    datetime(us.ssl_cert_valid_to/1000, 'unixepoch') as cert_expiry,
    (strftime('%s', 'now') * 1000 - us.ssl_cert_valid_to) / (1000 * 60 * 60 * 24.0) as days_expired
FROM url_status us
WHERE us.ssl_cert_valid_to IS NOT NULL
  AND us.ssl_cert_valid_to < strftime('%s', 'now') * 1000
ORDER BY days_expired DESC;
```

### 10. List certificate issuers

```sql
SELECT
    us.ssl_cert_issuer,
    COUNT(DISTINCT us.final_domain) as domain_count
FROM url_status us
WHERE us.ssl_cert_issuer IS NOT NULL
GROUP BY us.ssl_cert_issuer
ORDER BY domain_count DESC;
```

## DNS Analysis

### 11. Find all DNS records for a domain

```sql
-- Nameservers
SELECT
    us.final_domain,
    'NS' as record_type,
    uns.nameserver as record_value
FROM url_status us
JOIN url_nameservers uns ON us.id = uns.url_status_id
WHERE us.final_domain = 'example.com'  -- Replace with your domain

UNION ALL

-- TXT records
SELECT
    us.final_domain,
    'TXT' as record_type,
    utr.txt_record as record_value
FROM url_status us
JOIN url_txt_records utr ON us.id = utr.url_status_id
WHERE us.final_domain = 'example.com'

UNION ALL

-- MX records
SELECT
    us.final_domain,
    'MX' as record_type,
    umr.priority || ' ' || umr.mail_exchange as record_value
FROM url_status us
JOIN url_mx_records umr ON us.id = umr.url_status_id
WHERE us.final_domain = 'example.com'

ORDER BY record_type;
```

### 12. Find domains with SPF records

```sql
-- Option 1: From extracted SPF field
SELECT DISTINCT
    us.final_domain,
    us.spf_record
FROM url_status us
WHERE us.spf_record IS NOT NULL
ORDER BY us.final_domain;

-- Option 2: From TXT records
SELECT DISTINCT
    us.final_domain,
    utr.txt_record as spf_record
FROM url_status us
JOIN url_txt_records utr ON us.id = utr.url_status_id
WHERE utr.record_type = 'SPF'
ORDER BY us.final_domain;
```

### 13. Find domains with DMARC records

```sql
-- Option 1: From extracted DMARC field
SELECT DISTINCT
    us.final_domain,
    us.dmarc_record
FROM url_status us
WHERE us.dmarc_record IS NOT NULL
ORDER BY us.final_domain;

-- Option 2: From TXT records
SELECT DISTINCT
    us.final_domain,
    utr.txt_record as dmarc_record
FROM url_status us
JOIN url_txt_records utr ON us.id = utr.url_status_id
WHERE utr.record_type = 'DMARC'
ORDER BY us.final_domain;
```

## GeoIP Analysis

### 14. Find all domains by country

```sql
SELECT
    us.final_domain,
    us.domain,
    ug.country_code,
    ug.country_name,
    ug.city
FROM url_status us
JOIN url_geoip ug ON us.id = ug.url_status_id
ORDER BY ug.country_code, ug.city;
```

### 15. Count domains by country

```sql
SELECT
    ug.country_code,
    ug.country_name,
    COUNT(DISTINCT us.final_domain) as domain_count
FROM url_status us
JOIN url_geoip ug ON us.id = ug.url_status_id
GROUP BY ug.country_code, ug.country_name
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
    us1.domain,
    us1.status as status_run1,
    us2.status as status_run2,
    us1.timestamp as timestamp_run1,
    us2.timestamp as timestamp_run2
FROM url_status us1
JOIN url_status us2 ON us1.final_domain = us2.final_domain
WHERE us1.run_id = 'run_1234567890'  -- Replace with your run IDs
  AND us2.run_id = 'run_1234567891'
  AND us1.status != us2.status;
```

### 18. Find new technologies detected in latest run

```sql
-- Compare technologies between two runs
SELECT DISTINCT
    ut2.technology_name as new_technology,
    ut2.technology_category,
    us2.final_domain
FROM url_technologies ut2
JOIN url_status us2 ON ut2.url_status_id = us2.id
WHERE us2.run_id = (SELECT run_id FROM runs ORDER BY start_time DESC LIMIT 1)
  AND NOT EXISTS (
    SELECT 1
    FROM url_technologies ut1
    JOIN url_status us1 ON ut1.url_status_id = us1.id
    WHERE us1.run_id = (SELECT run_id FROM runs ORDER BY start_time DESC LIMIT 1 OFFSET 1)
      AND ut1.technology_name = ut2.technology_name
      AND us1.final_domain = us2.final_domain
  )
ORDER BY us2.final_domain, ut2.technology_category;
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
    domain,
    final_domain,
    response_time,
    timestamp
FROM url_status
WHERE response_time IS NOT NULL
ORDER BY response_time DESC
LIMIT 20;
```

### 22. Average response time by domain

```sql
SELECT
    final_domain,
    AVG(response_time) as avg_response_time,
    MIN(response_time) as min_response_time,
    MAX(response_time) as max_response_time,
    COUNT(*) as request_count
FROM url_status
WHERE response_time IS NOT NULL
GROUP BY final_domain
ORDER BY avg_response_time DESC;
```

## Security Analysis

### 23. Find domains without HTTPS

```sql
SELECT
    domain,
    final_domain,
    status
FROM url_status
WHERE tls_version IS NULL
ORDER BY final_domain;
```

### 24. Find domains with security warnings

```sql
SELECT
    us.domain,
    us.final_domain,
    usw.warning_code,
    usw.warning_description
FROM url_status us
JOIN url_security_warnings usw ON us.id = usw.url_status_id
ORDER BY us.final_domain, usw.warning_code;
```

## Advanced Queries

### 25. Complete domain summary

```sql
SELECT
    us.final_domain,
    COUNT(DISTINCT us.id) as url_count,
    MIN(us.status) as min_status,
    MAX(us.status) as max_status,
    AVG(us.response_time) as avg_response_time,
    COUNT(DISTINCT ut.technology_name) as technology_count,
    GROUP_CONCAT(DISTINCT ut.technology_category) as technology_categories
FROM url_status us
LEFT JOIN url_technologies ut ON us.id = ut.url_status_id
GROUP BY us.final_domain
ORDER BY url_count DESC;
```

### 26. Find domains with multiple redirects

```sql
SELECT
    us.final_domain,
    us.domain,
    COUNT(urc.id) as redirect_count,
    GROUP_CONCAT(urc.url, ' -> ') as redirect_chain
FROM url_status us
JOIN url_redirect_chain urc ON us.id = urc.url_status_id
GROUP BY us.id
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
SELECT * FROM url_status WHERE status = 200;
EOF
```

Or use the export subcommand to export filtered results:

```bash
domain_status export --db-path domain_status.db --format csv --status 200 --output successful.csv
```
