# Database Schema

`domain_status` stores scan results in a single SQLite database, defaulting to `./domain_status.db`.

The schema is created by migrations (`migrations/0001_initial_schema.sql` through `migrations/0008_jwt_claims.sql`) and follows a simple pattern:

- `runs` stores run-level metadata
- `url_status` stores one successful observation row per URL result
- `url_failures` stores failed URL attempts
- most other tables are satellite tables hanging off `url_status` or `url_failures`

## High-Level Shape

```mermaid
erDiagram
    runs ||--o{ url_status : has
    runs ||--o{ url_failures : has

    url_status ||--o{ url_technologies : has
    url_status ||--o{ url_redirect_chain : has
    url_status ||--o{ url_nameservers : has
    url_status ||--o{ url_txt_records : has
    url_status ||--o{ url_mx_records : has
    url_status ||--o{ url_security_headers : has
    url_status ||--o{ url_http_headers : has
    url_status ||--o{ url_certificate_oids : has
    url_status ||--o{ url_certificate_sans : has
    url_status ||--o| url_geoip : has
    url_status ||--o| url_whois : has
    url_status ||--o{ url_structured_data : has
    url_status ||--o{ url_social_media_links : has
    url_status ||--o{ url_analytics_ids : has
    url_status ||--o{ url_security_warnings : has
    url_status ||--o| url_favicons : has
    url_status ||--o{ url_contact_links : has
    url_status ||--o{ url_exposed_secrets : has
    url_status ||--o{ url_partial_failures : has
    url_status ||--o{ url_cname_records : has
    url_status ||--o{ url_ipv6_addresses : has
    url_status ||--o{ url_caa_records : has
    url_status ||--o{ url_csp_domains : has
    url_status ||--o{ url_cookies : has
    url_status ||--o{ url_resource_hints : has
    url_status ||--o{ url_script_hosts : has
    url_status ||--o{ url_body_domains : has

    url_exposed_secrets ||--o| url_jwt_claims : has

    url_failures ||--o{ url_failure_redirect_chain : has
    url_failures ||--o{ url_failure_response_headers : has
    url_failures ||--o{ url_failure_request_headers : has
```

## Core Tables

### `runs`

One row per scan invocation.

| Column | Type | Notes |
|--------|------|-------|
| `run_id` | `TEXT PRIMARY KEY` | Generated as `run_<epoch_ms>` |
| `version` | `TEXT` | Application version |
| `fingerprints_source` | `TEXT` | Source URL/path used for fingerprint initialization |
| `fingerprints_version` | `TEXT` | Fingerprint ruleset version/commit |
| `geoip_version` | `TEXT` | GeoIP database version when available |
| `start_time_ms` | `INTEGER NOT NULL` | Scan start time |
| `end_time_ms` | `INTEGER` | Nullable until completion |
| `elapsed_seconds` | `REAL` | Populated at finalization |
| `total_urls` | `INTEGER DEFAULT 0` | Total URLs attempted |
| `successful_urls` | `INTEGER DEFAULT 0` | Successful URL observations |
| `failed_urls` | `INTEGER DEFAULT 0` | Failed URL attempts |
| `skipped_urls` | `INTEGER DEFAULT 0` | URLs intentionally skipped (e.g. duplicate domain in same run) |

### `url_status`

The main fact table for successful URL observations.

Important characteristics:

- stores the final observed domain after redirects
- keeps `ip_address` as `TEXT NOT NULL`
- uses `observed_at_ms` for run-time uniqueness
- links back to `runs.run_id`

| Column | Type | Notes |
|--------|------|-------|
| `id` | `INTEGER PRIMARY KEY AUTOINCREMENT` | Surrogate key |
| `initial_domain` | `TEXT NOT NULL` | Domain from the input URL |
| `final_domain` | `TEXT NOT NULL` | Domain after redirects |
| `initial_url` | `TEXT` | Original request URL (scheme/host/path/query) before redirects |
| `final_url` | `TEXT` | Final URL after redirects (scheme/host/path/query) |
| `ip_address` | `TEXT NOT NULL` | Resolved IP address; empty string is possible when no IP was persisted |
| `reverse_dns_name` | `TEXT` | PTR result when available |
| `http_status` | `INTEGER NOT NULL` | HTTP status code |
| `http_status_text` | `TEXT NOT NULL` | Human-readable status |
| `response_time_seconds` | `REAL NOT NULL` | Response time |
| `title` | `TEXT NOT NULL` | Empty string when missing |
| `keywords` | `TEXT` | **Deprecated — no longer written.** Column retained for old DBs. Previously `<meta name="keywords">` (obsolete SEO). |
| `description` | `TEXT` | Optional meta description |
| `meta_robots` | `TEXT` | Content of `<meta name="robots">` when present |
| `is_mobile_friendly` | `BOOLEAN NOT NULL DEFAULT 0` | **Deprecated — always written as `0`.** Previously a viewport-meta heuristic only. |
| `tls_version` | `TEXT` | Nullable for HTTP-only or missing TLS data |
| `cipher_suite` | `TEXT` | Captured TLS cipher suite |
| `key_algorithm` | `TEXT` | Parsed certificate key algorithm |
| `ssl_cert_subject` | `TEXT` | Certificate subject |
| `ssl_cert_issuer` | `TEXT` | Certificate issuer |
| `ssl_cert_valid_from_ms` | `INTEGER` | Epoch milliseconds |
| `ssl_cert_valid_to_ms` | `INTEGER` | Epoch milliseconds |
| `spf_record` | `TEXT` | Convenience extraction from TXT records |
| `dmarc_record` | `TEXT` | Convenience extraction from TXT records |
| `body_sha256` | `TEXT` | SHA-256 hash of the response body (content fingerprinting) |
| `body_truncated` | `INTEGER NOT NULL DEFAULT 0` | 1 if the body hit the 2 MB scan cap (prefix still scanned) |
| `external_scripts_eligible` | `INTEGER NOT NULL DEFAULT 0` | First-party `<script src>` candidates when `--scan-external-scripts` is on |
| `external_scripts_scanned` | `INTEGER NOT NULL DEFAULT 0` | Scripts successfully fetched/scanned for secrets (capped; 0 when flag off) |
| `content_length` | `INTEGER` | Response body length in bytes |
| `http_version` | `TEXT` | HTTP protocol version (`HTTP/1.1`, `HTTP/2`, etc.) |
| `body_word_count` | `INTEGER` | **Deprecated — no longer written** (prefer `content_length` + `body_sha256`). |
| `body_line_count` | `INTEGER` | **Deprecated — no longer written.** |
| `content_type` | `TEXT` | Content-Type header value |
| `canonical_url` | `TEXT` | URL from `<link rel="canonical">` |
| `cert_fingerprint_sha256` | `TEXT` | SHA-256 hash of the leaf TLS certificate DER |
| `cert_serial_number` | `TEXT` | Certificate serial number |
| `cert_is_self_signed` | `BOOLEAN` | Whether issuer == subject |
| `cert_is_wildcard` | `BOOLEAN` | Whether any SAN starts with `*.` |
| `cert_is_mismatched` | `BOOLEAN` | Whether cert doesn't match requested domain |
| `meta_refresh_url` | `TEXT` | Client-side redirect from `<meta http-equiv="refresh">` |
| `observed_at_ms` | `INTEGER NOT NULL` | Observation timestamp |
| `run_id` | `TEXT` | FK to `runs.run_id` |

Constraint:

```sql
UNIQUE(final_domain, observed_at_ms)
```

### `url_failures`

Stores failed URL processing attempts.

| Column | Type | Notes |
|--------|------|-------|
| `id` | `INTEGER PRIMARY KEY AUTOINCREMENT` | Surrogate key |
| `attempted_url` | `TEXT NOT NULL` | Original URL attempted |
| `final_url` | `TEXT` | Last URL reached before failing |
| `initial_domain` | `TEXT NOT NULL` | Domain from the original URL |
| `final_domain` | `TEXT` | Domain after redirects if known |
| `error_type` | `TEXT NOT NULL` | Categorized error type |
| `error_message` | `TEXT NOT NULL` | Stored failure message |
| `http_status` | `INTEGER` | Status code when available |
| `retry_count` | `INTEGER NOT NULL DEFAULT 0` | Attempts consumed |
| `elapsed_time_seconds` | `REAL` | Optional elapsed time |
| `observed_at_ms` | `INTEGER NOT NULL` | Failure timestamp |
| `run_id` | `TEXT` | FK to `runs.run_id` |

### `url_partial_failures`

Captures non-fatal enrichment failures associated with otherwise successful `url_status` rows.

| Column | Type | Notes |
|--------|------|-------|
| `url_status_id` | `INTEGER NOT NULL` | FK to `url_status.id` |
| `error_type` | `TEXT NOT NULL` | Supplemental failure type |
| `error_message` | `TEXT NOT NULL` | Failure detail |
| `observed_at_ms` | `INTEGER NOT NULL` | Timestamp |
| `run_id` | `TEXT` | Optional FK to `runs.run_id` |

## Successful-Observation Satellites

### DNS and redirect satellites

| Table | Purpose | Key columns |
|------|---------|-------------|
| `url_redirect_chain` | Ordered redirect history | `sequence_order`, `redirect_url`, `http_status` |
| `url_nameservers` | Expanded nameserver rows | `nameserver` |
| `url_txt_records` | Expanded TXT record rows | `record_type`, `record_value` |
| `url_mx_records` | Expanded MX rows | `priority`, `mail_exchange` |
| `url_cname_records` | CNAME targets (CDN/hosting infrastructure) | `cname_target` |
| `url_ipv6_addresses` | AAAA records (IPv6 dual-stack detection) | `ipv6_address` |
| `url_caa_records` | Certificate Authority Authorization | `flag`, `tag`, `value` |
| `url_csp_domains` | Domains from Content-Security-Policy | `directive`, `fqdn`, `registrable_domain` |
| `url_cookies` | Cookie security attributes | `cookie_name`, `secure`, `http_only`, `same_site`, `domain`, `path` |
| `url_resource_hints` | `<link>` resource hints: preconnect, dns-prefetch, preload, prefetch, modulepreload (`hint_type` stored lowercase) | `hint_type`, `href` |
| `url_script_hosts` | Unique hosts from `<script src>` (resolved against final URL) | `host`, `registrable_domain`, `is_first_party` |
| `url_body_domains` | **Deprecated — no longer populated.** Table retained for old DBs. Prefer `url_csp_domains`, `url_analytics_ids`, `url_social_media_links`. | `fqdn`, `registrable_domain` |

> **Note on `url_cname_records` and apex domains:** DNS forbids a CNAME record at
> a zone apex (e.g. `example.com`), so this table is typically empty for
> root-domain scans — real CNAME data mostly shows up for `www.`/subdomain
> targets. Some registrars/CDNs "flatten" apex aliasing (ALIAS/ANAME or
> provider-side flattening) to a plain A/AAAA record, which is invisible here.
> Don't read an empty `url_cname_records` row as "not behind a CDN."

### HTTP and TLS satellites

| Table | Purpose | Key columns |
|------|---------|-------------|
| `url_http_headers` | Captured HTTP response headers | `header_name`, `header_value` |
| `url_security_headers` | Security-focused header subset | `header_name`, `header_value` |
| `url_certificate_oids` | Certificate OIDs | `oid` |
| `url_certificate_sans` | Certificate SANs | `san_value` |
| `url_favicons` | Favicon URL + Shodan-compatible hash. `base64_data` is **no longer written** (storage bomb; column retained nullable for old DBs). | `favicon_url`, `hash`, `base64_data` |

### Enrichment satellites

| Table | Purpose | Key columns |
|------|---------|-------------|
| `url_geoip` | GeoIP/ASN enrichment | `country_code`, `country_name`, `region`, `city`, `latitude`, `longitude`, `postal_code`, `timezone`, `asn`, `asn_org` |
| `url_whois` | WHOIS/RDAP enrichment | `creation_date_ms`, `expiration_date_ms`, `updated_date_ms`, `registrar`, `registrant_country`, `registrant_org`, `whois_statuses`, `nameservers_json`, `raw_response` |
| `url_structured_data` | JSON-LD, Open Graph, Twitter, schema-derived properties | `data_type`, `property_name`, `property_value` |
| `url_social_media_links` | Social profile links | `platform`, `profile_url`, `identifier` |
| `url_analytics_ids` | Analytics/tracking IDs | `provider`, `tracking_id` |
| `url_contact_links` | `mailto:` and `tel:` links | `contact_type`, `contact_value`, `raw_href` |
| `url_security_warnings` | Real, observed security issues only — see note below | `warning_code`, `warning_description` |
| `url_technologies` | Directly observed fingerprint matches. `HTTP/3` and `HSTS` are **not** inserted (use headers / `http_version` / TLS). Export/summary default to `is_implied = 0`; use `--include-implied-tech` on export to include implied rows. | `technology_name`, `technology_version`, `technology_category`, `is_implied` |
| `url_exposed_secrets` | Gitleaks-style secret findings in page content | `secret_type`, `matched_value`, `severity`, `location`, `context` |
| `url_jwt_claims` | Decoded JWT header + payload (1:1 with `url_exposed_secrets`) | `header_json`, `payload_json`, `algorithm`, `issuer`, `subject`, `expiration_ms` |

## Failure Satellites

These tables hang off `url_failures.id`:

| Table | Purpose |
|------|---------|
| `url_failure_redirect_chain` | Redirect history captured before failure |
| `url_failure_response_headers` | Response headers observed before failure |
| `url_failure_request_headers` | **Deprecated — no longer written** on new failures (echo of scanner outbound headers). Table retained for old DBs. |

## Relationship Semantics

- Most `url_status` satellites use `FOREIGN KEY ... ON DELETE CASCADE`.
- `url_status.run_id` and `url_failures.run_id` reference `runs(run_id)`.
- `url_whois` and `url_geoip` are one-to-one enrichments per successful observation.
- `url_jwt_claims` is a one-to-one enrichment per `url_exposed_secrets` row (only populated for `jwt`/`jwt-base64` secret types).
- `UNIQUE(run_id, final_domain)` ensures at most one `url_status` row per domain per run.
- Several multi-valued concepts are normalized into child tables rather than stored inline.

## Schema Notes That Commonly Matter

### WHOIS naming

The current `url_whois` schema uses:

- `registrant_org`
- `whois_statuses`
- `nameservers_json`
- `raw_response`

These names replace older or more ambiguous variants that may appear in stale docs or old queries.

### Security warnings

`url_security_warnings` only stores warnings for issues actually observed on the
target: `no_https`, `weak_tls`, and `invalid_certificate`. It does **not** store a
"missing header" finding for absent `Strict-Transport-Security`,
`Content-Security-Policy`, `X-Content-Type-Options`, or `X-Frame-Options` headers —
those are checklist/absence checks, not evidence of a problem, and every plain site
without those headers would otherwise produce the same four rows, drowning out the
warnings that represent something actually wrong. Header presence is fully
queryable without a precomputed warning: absence of a given `header_name` for a
`url_status_id` in `url_security_headers` **is** the "missing header" signal, e.g.:

```sql
SELECT s.final_domain
FROM url_status s
WHERE NOT EXISTS (
    SELECT 1 FROM url_security_headers h
    WHERE h.url_status_id = s.id AND h.header_name = 'Strict-Transport-Security'
);
```

The raw `Strict-Transport-Security` header value (when present) is stored verbatim
in `url_security_headers`, e.g. `max-age=31536000; includeSubDomains; preload`. Its
`max-age` / `includeSubDomains` / `preload` directives aren't broken out into
separate columns (to avoid schema churn for a header most sites don't send), but
they're straightforward to parse from that single value if needed for analysis.

### Legacy databases (pre–data-capture cleanup)

Scans produced with **v0.1.26 and earlier** may still contain:

- `missing_csp` / `missing_hsts` / `missing_frame_options` / `missing_content_type_options` in `url_security_warnings` (checklist noise). Filter with:

```sql
SELECT * FROM url_security_warnings
WHERE warning_code NOT LIKE 'missing_%';
```

- Empty TLS on rows whose `ip_address` is IPv6 (no IPv4 fallback yet). Prefer newer binaries for dual-stack cert coverage.
- Populated `keywords`, `body_word_count` / `body_line_count`, `url_body_domains`, favicon `base64_data`, and `url_failure_request_headers`.

Optional maintenance to reclaim disk from old favicon payloads:

```sql
UPDATE url_favicons SET base64_data = NULL WHERE base64_data IS NOT NULL AND base64_data != '';
VACUUM;
```

### Secret findings

`url_exposed_secrets.secret_type` stores the rule identifier used by the scanner, while:

- `matched_value` stores the matched secret text
- `severity` stores the classifier severity
- `location` stores where it was found (`inline_script`, `json_ld`, `html_comment`, `data_attribute`, `url_parameter`, `meta_tag`, `html_body`, `response_header`, `set_cookie`, or `external_script:<url>`)
- Join `url_status.body_truncated` / `external_scripts_*` when assessing whether a miss is possible due to size caps or script limits
- `context` stores nearby source text for analyst review

Uniqueness is enforced by:

```sql
UNIQUE(url_status_id, secret_type, matched_value)
```

## Query Examples

Recent runs:

```sql
SELECT run_id, version, start_time_ms, end_time_ms, total_urls, successful_urls, failed_urls
FROM runs
ORDER BY start_time_ms DESC
LIMIT 20;
```

Successful observations for a run:

```sql
SELECT final_domain, http_status, title, observed_at_ms
FROM url_status
WHERE run_id = 'run_1700000000000'
ORDER BY observed_at_ms DESC;
```

WHOIS enrichment with the current column names:

```sql
SELECT s.final_domain, w.registrar, w.registrant_country, w.registrant_org, w.whois_statuses
FROM url_status AS s
JOIN url_whois AS w ON w.url_status_id = s.id
WHERE s.run_id = 'run_1700000000000';
```

Secret findings by type:

```sql
SELECT secret_type, severity, COUNT(*) AS findings
FROM url_exposed_secrets
GROUP BY secret_type, severity
ORDER BY findings DESC, secret_type;
```

Decoded JWT claims for exposed tokens:

```sql
SELECT es.secret_type, jc.algorithm, jc.issuer, jc.subject,
       datetime(jc.expiration_ms/1000, 'unixepoch') AS expires
FROM url_jwt_claims jc
JOIN url_exposed_secrets es ON es.id = jc.exposed_secret_id
JOIN url_status s ON s.id = es.url_status_id
ORDER BY jc.expiration_ms DESC;
```

## Operational Notes

- Scans write into the default database unless `--db-path` is supplied.
- Exports read from that same database path by default.
- The application enables WAL mode and foreign keys during pool initialization.
- For the source of truth, prefer the migration file over old ad-hoc SQL snippets.
