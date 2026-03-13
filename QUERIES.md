# SQLite Query Examples

This document provides common SQL queries for analyzing `domain_status` scan results.

## Basic Queries

### 1. List all scanned URLs with status codes

```sql
SELECT
    initial_domain,
    http_status,
    final_domain,
    datetime(observed_at_ms/1000, 'unixepoch') as scanned_at
FROM url_status
ORDER BY observed_at_ms DESC;
```

### 2. Find all failed URLs

```sql
SELECT
    initial_domain,
    error_type,
    error_message,
    datetime(observed_at_ms/1000, 'unixepoch') as scanned_at
FROM url_failures
ORDER BY observed_at_ms DESC;
```

### 3. Find all redirects

```sql
SELECT
    us.initial_domain,
    us.final_domain,
    us.http_status,
    COUNT(urc.id) as redirect_count
FROM url_status us
LEFT JOIN url_redirect_chain urc ON us.id = urc.url_status_id
WHERE urc.id IS NOT NULL
GROUP BY us.id
ORDER BY redirect_count DESC;
```

### 4. View redirect chains (with status codes per hop)

```sql
SELECT
    us.initial_domain,
    urc.redirect_url,
    urc.http_status,
    urc.sequence_order
FROM url_status us
JOIN url_redirect_chain urc ON us.id = urc.url_status_id
ORDER BY us.id, urc.sequence_order;
```

## Technology Detection

### 5. Find all detected technologies

```sql
SELECT
    us.initial_domain,
    us.final_domain,
    ut.technology_name,
    ut.technology_version,
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
    us.initial_domain,
    ut.technology_version
FROM url_status us
JOIN url_technologies ut ON us.id = ut.url_status_id
WHERE ut.technology_name = 'WordPress'  -- Replace with your technology
ORDER BY us.final_domain;
```

## TLS Certificate Analysis

### 8. Find certificates expiring soon (within 30 days)

```sql
SELECT
    us.initial_domain,
    us.final_domain,
    datetime(us.ssl_cert_valid_to_ms/1000, 'unixepoch') as cert_expiry,
    CAST((us.ssl_cert_valid_to_ms - strftime('%s', 'now') * 1000) / (1000.0 * 60 * 60 * 24) AS INTEGER) as days_until_expiry
FROM url_status us
WHERE us.ssl_cert_valid_to_ms IS NOT NULL
  AND (us.ssl_cert_valid_to_ms - strftime('%s', 'now') * 1000) / (1000.0 * 60 * 60 * 24) BETWEEN 0 AND 30
ORDER BY days_until_expiry ASC;
```

### 9. Find all expired certificates

```sql
SELECT
    us.initial_domain,
    us.final_domain,
    datetime(us.ssl_cert_valid_to_ms/1000, 'unixepoch') as cert_expiry,
    CAST((strftime('%s', 'now') * 1000 - us.ssl_cert_valid_to_ms) / (1000.0 * 60 * 60 * 24) AS INTEGER) as days_expired
FROM url_status us
WHERE us.ssl_cert_valid_to_ms IS NOT NULL
  AND us.ssl_cert_valid_to_ms < strftime('%s', 'now') * 1000
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
SELECT us.final_domain, 'NS' as record_type, uns.nameserver as record_value
FROM url_status us
JOIN url_nameservers uns ON us.id = uns.url_status_id
WHERE us.final_domain = 'example.com'  -- Replace with your domain

UNION ALL

-- TXT records
SELECT us.final_domain, utr.record_type, utr.record_value
FROM url_status us
JOIN url_txt_records utr ON us.id = utr.url_status_id
WHERE us.final_domain = 'example.com'

UNION ALL

-- MX records
SELECT us.final_domain, 'MX' as record_type, umr.priority || ' ' || umr.mail_exchange as record_value
FROM url_status us
JOIN url_mx_records umr ON us.id = umr.url_status_id
WHERE us.final_domain = 'example.com'

ORDER BY record_type;
```

### 12. Find domains with SPF records

```sql
-- Option 1: From extracted SPF field
SELECT DISTINCT us.final_domain, us.spf_record
FROM url_status us
WHERE us.spf_record IS NOT NULL
ORDER BY us.final_domain;

-- Option 2: From TXT records
SELECT DISTINCT us.final_domain, utr.record_value as spf_record
FROM url_status us
JOIN url_txt_records utr ON us.id = utr.url_status_id
WHERE utr.record_type = 'SPF'
ORDER BY us.final_domain;
```

### 13. Find domains with DMARC records

```sql
-- Option 1: From extracted DMARC field
SELECT DISTINCT us.final_domain, us.dmarc_record
FROM url_status us
WHERE us.dmarc_record IS NOT NULL
ORDER BY us.final_domain;

-- Option 2: From TXT records
SELECT DISTINCT us.final_domain, utr.record_value as dmarc_record
FROM url_status us
JOIN url_txt_records utr ON us.id = utr.url_status_id
WHERE utr.record_type = 'DMARC'
ORDER BY us.final_domain;
```

### 14. Find CNAME records (CDN/hosting infrastructure)

```sql
SELECT us.final_domain, cr.cname_target
FROM url_cname_records cr
JOIN url_status us ON us.id = cr.url_status_id
ORDER BY us.final_domain;
```

### 15. Find domains with IPv6 support

```sql
SELECT us.final_domain, ia.ipv6_address
FROM url_ipv6_addresses ia
JOIN url_status us ON us.id = ia.url_status_id
ORDER BY us.final_domain;
```

### 16. Find CAA records (authorized certificate authorities)

```sql
SELECT us.final_domain, cr.flag, cr.tag, cr.value
FROM url_caa_records cr
JOIN url_status us ON us.id = cr.url_status_id
ORDER BY us.final_domain, cr.tag;
```

## Content Fingerprinting

### 17. Find domains with identical page content (same body hash)

```sql
SELECT body_sha256, COUNT(*) as cnt, GROUP_CONCAT(final_domain) as domains
FROM url_status
WHERE body_sha256 IS NOT NULL
GROUP BY body_sha256
HAVING cnt > 1;
```

### 18. Find domains sharing the same TLS certificate fingerprint

```sql
SELECT cert_fingerprint_sha256, COUNT(*) as cnt, GROUP_CONCAT(final_domain) as domains
FROM url_status
WHERE cert_fingerprint_sha256 IS NOT NULL
GROUP BY cert_fingerprint_sha256
HAVING cnt > 1;
```

### 19. HTTP version distribution

```sql
SELECT http_version, COUNT(*) as cnt
FROM url_status
GROUP BY http_version
ORDER BY cnt DESC;
```

## GeoIP Analysis

### 20. Find all domains by country

```sql
SELECT
    us.final_domain,
    us.initial_domain,
    ug.country_code,
    ug.country_name,
    ug.city
FROM url_status us
JOIN url_geoip ug ON us.id = ug.url_status_id
ORDER BY ug.country_code, ug.city;
```

### 21. Count domains by country

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

### 22. List all scan runs

```sql
SELECT
    run_id,
    version,
    datetime(start_time_ms/1000, 'unixepoch') as started_at,
    elapsed_seconds,
    total_urls,
    successful_urls,
    failed_urls,
    skipped_urls
FROM runs
ORDER BY start_time_ms DESC;
```

### 23. Compare results between runs

```sql
-- Find URLs that changed status between runs
SELECT
    us1.initial_domain,
    us1.http_status as status_run1,
    us2.http_status as status_run2
FROM url_status us1
JOIN url_status us2 ON us1.final_domain = us2.final_domain
WHERE us1.run_id = 'run_1234567890'  -- Replace with your run IDs
  AND us2.run_id = 'run_1234567891'
  AND us1.http_status != us2.http_status;
```

### 24. Find new technologies detected in latest run

```sql
SELECT DISTINCT
    ut2.technology_name as new_technology,
    ut2.technology_category,
    us2.final_domain
FROM url_technologies ut2
JOIN url_status us2 ON ut2.url_status_id = us2.id
WHERE us2.run_id = (SELECT run_id FROM runs ORDER BY start_time_ms DESC LIMIT 1)
  AND NOT EXISTS (
    SELECT 1
    FROM url_technologies ut1
    JOIN url_status us1 ON ut1.url_status_id = us1.id
    WHERE us1.run_id = (SELECT run_id FROM runs ORDER BY start_time_ms DESC LIMIT 1 OFFSET 1)
      AND ut1.technology_name = ut2.technology_name
      AND us1.final_domain = us2.final_domain
  )
ORDER BY us2.final_domain, ut2.technology_category;
```

## Error Analysis

### 25. Find all errors by type

```sql
SELECT
    error_type,
    COUNT(*) as error_count,
    COUNT(DISTINCT initial_domain) as affected_domains
FROM url_failures
GROUP BY error_type
ORDER BY error_count DESC;
```

### 26. Find domains with most failures

```sql
SELECT
    initial_domain,
    COUNT(*) as failure_count,
    GROUP_CONCAT(DISTINCT error_type) as error_types
FROM url_failures
GROUP BY initial_domain
ORDER BY failure_count DESC
LIMIT 20;
```

## Performance Analysis

### 27. Find slowest URLs (by response time)

```sql
SELECT
    initial_domain,
    final_domain,
    response_time_seconds,
    datetime(observed_at_ms/1000, 'unixepoch') as scanned_at
FROM url_status
ORDER BY response_time_seconds DESC
LIMIT 20;
```

### 28. Average response time by domain

```sql
SELECT
    final_domain,
    ROUND(AVG(response_time_seconds), 3) as avg_response_time,
    ROUND(MIN(response_time_seconds), 3) as min_response_time,
    ROUND(MAX(response_time_seconds), 3) as max_response_time,
    COUNT(*) as request_count
FROM url_status
GROUP BY final_domain
ORDER BY avg_response_time DESC;
```

## Security Analysis

### 29. Find domains without TLS

```sql
SELECT
    initial_domain,
    final_domain,
    http_status
FROM url_status
WHERE tls_version IS NULL
ORDER BY final_domain;
```

### 30. Find domains with security warnings

```sql
SELECT
    us.initial_domain,
    us.final_domain,
    usw.warning_code,
    usw.warning_description
FROM url_status us
JOIN url_security_warnings usw ON us.id = usw.url_status_id
ORDER BY us.final_domain, usw.warning_code;
```

### 31. Find exposed secrets (sorted by severity)

```sql
SELECT
    us.initial_domain,
    es.secret_type,
    es.severity,
    es.location,
    es.matched_value,
    es.context
FROM url_exposed_secrets es
JOIN url_status us ON es.url_status_id = us.id
ORDER BY
    CASE es.severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
    END,
    us.initial_domain;
```

### 32. Count exposed secrets by type

```sql
SELECT
    secret_type,
    severity,
    COUNT(*) as count,
    COUNT(DISTINCT url_status_id) as affected_domains
FROM url_exposed_secrets
GROUP BY secret_type, severity
ORDER BY
    CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 END,
    count DESC;
```

## Contact Information

### 33. Find all email contacts

```sql
SELECT
    us.initial_domain,
    cl.contact_value as email,
    cl.raw_href
FROM url_contact_links cl
JOIN url_status us ON cl.url_status_id = us.id
WHERE cl.contact_type = 'email'
ORDER BY us.initial_domain;
```

### 34. Find all phone contacts

```sql
SELECT
    us.initial_domain,
    cl.contact_value as phone,
    cl.raw_href
FROM url_contact_links cl
JOIN url_status us ON cl.url_status_id = us.id
WHERE cl.contact_type = 'phone'
ORDER BY us.initial_domain;
```

## Advanced Queries

### 35. Complete domain summary

```sql
SELECT
    us.final_domain,
    COUNT(DISTINCT us.id) as url_count,
    us.http_status,
    ROUND(us.response_time_seconds, 3) as response_time,
    COUNT(DISTINCT ut.technology_name) as technology_count,
    GROUP_CONCAT(DISTINCT ut.technology_name) as technologies
FROM url_status us
LEFT JOIN url_technologies ut ON us.id = ut.url_status_id
GROUP BY us.final_domain
ORDER BY url_count DESC;
```

### 36. Find domains with multiple redirects

```sql
SELECT
    us.final_domain,
    us.initial_domain,
    COUNT(urc.id) as redirect_count,
    GROUP_CONCAT(urc.redirect_url, ' -> ') as redirect_chain
FROM url_status us
JOIN url_redirect_chain urc ON us.id = urc.url_status_id
GROUP BY us.id
HAVING redirect_count > 3
ORDER BY redirect_count DESC;
```

### 37. Find domains sharing the same TLS certificate

```sql
SELECT
    san.san_value,
    COUNT(DISTINCT us.final_domain) as domain_count,
    GROUP_CONCAT(DISTINCT us.final_domain) as domains
FROM url_certificate_sans san
JOIN url_status us ON san.url_status_id = us.id
GROUP BY san.san_value
HAVING domain_count > 1
ORDER BY domain_count DESC;
```

## JWT Claims Analysis

### 38. Find decoded JWT claims from exposed tokens

```sql
SELECT
    us.final_domain,
    es.secret_type,
    jc.algorithm,
    jc.issuer,
    jc.subject,
    datetime(jc.expiration_ms/1000, 'unixepoch') as expires,
    datetime(jc.issued_at_ms/1000, 'unixepoch') as issued_at
FROM url_jwt_claims jc
JOIN url_exposed_secrets es ON es.id = jc.exposed_secret_id
JOIN url_status us ON us.id = es.url_status_id
ORDER BY jc.expiration_ms DESC;
```

### 39. Count JWT tokens by algorithm and issuer

```sql
SELECT
    jc.algorithm,
    jc.issuer,
    COUNT(*) as token_count
FROM url_jwt_claims jc
GROUP BY jc.algorithm, jc.issuer
ORDER BY token_count DESC;
```

## Query validation (MCP-tested)

Queries were run against a SQLite DB via the SQLite MCP. Failures are due to **schema evolution**: the test DB was on an older schema; every missing table/column **does exist** in the migrations (see below).

| #   | Status  | Notes |
|-----|--------|--------|
| 1–3 | OK     | Return rows. |
| 4   | **FAIL** | `no such column: urc.http_status` — column added in **0006_osint_signals.sql** (`ALTER TABLE url_redirect_chain ADD COLUMN http_status INTEGER`). |
| 5–13 | OK    | Return rows (or empty). Query 11 uses placeholder `example.com`; replace with a domain you have. |
| 14  | **FAIL** | `no such table: url_cname_records` — table created in **0006_osint_signals.sql**. |
| 15  | **FAIL** | `no such table: url_ipv6_addresses` — table created in **0006_osint_signals.sql**. |
| 16  | **FAIL** | `no such table: url_caa_records` — table created in **0006_osint_signals.sql**. |
| 17  | **FAIL** | `no such column: body_sha256` — added in **0006_osint_signals.sql** on `url_status`. |
| 18  | **FAIL** | `no such column: cert_fingerprint_sha256` — added in **0006_osint_signals.sql** on `url_status`. |
| 19  | **FAIL** | `no such column: http_version` — added in **0006_osint_signals.sql** on `url_status`. |
| 20–21 | OK   | Return rows or empty. |
| 22  | **FAIL** | `no such column: skipped_urls` — added in **0004_add_skipped_urls_to_runs.sql** on `runs`. |
| 23–37 | OK   | Return rows or empty. |
| 38  | **FAIL** | `no such table: url_jwt_claims` — table created in **0008_jwt_claims.sql**. |
| 39  | **FAIL** | `no such table: url_jwt_claims` — same as 38. |

**Summary:** All failures are from running against a DB that has not had the full migration set applied. The queries are correct for the current schema. Apply migrations in order (0004 → 0006 → 0008) and all 39 queries should run.

## Tips

- Use `datetime(observed_at_ms/1000, 'unixepoch')` to format timestamps as readable dates
- The `run_id` field links records to specific scan runs
- Timestamps are stored as milliseconds since epoch (`observed_at_ms`, `start_time_ms`, `ssl_cert_valid_to_ms`)
- Use `GROUP_CONCAT()` to aggregate multiple values into a single column
- Join with `runs` table to filter by scan version or date

## Exporting Results

To export query results to CSV:

```bash
sqlite3 domain_status.db <<EOF
.headers on
.mode csv
.output results.csv
SELECT initial_domain, http_status, title FROM url_status WHERE http_status = 200;
EOF
```

Or use the built-in export command:

```bash
domain_status export --db-path domain_status.db --format csv --status 200 --output successful.csv
```
