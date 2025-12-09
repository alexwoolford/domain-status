# Serialization Design for Nested Data

## Problem Statement

The `domain_status` data model is inherently nested:
- One URL record can have multiple redirects (1-to-many)
- One URL record can have multiple technologies (1-to-many)
- One URL record can have multiple DNS records (1-to-many)
- One URL record can have multiple security warnings (1-to-many)
- One URL record can have one GeoIP result (1-to-1, but nested structure)
- One URL record can have one WHOIS result (1-to-1, but nested structure)
- One URL record can have one structured data result (1-to-1, but nested structure)

This nested structure doesn't map cleanly to flat formats like CSV without data duplication or loss.

## Data Structure Overview

### BatchRecord Structure

```rust
pub struct BatchRecord {
    pub url_record: UrlRecord,                    // Flat structure
    pub security_headers: HashMap<String, String>, // Key-value pairs
    pub http_headers: HashMap<String, String>,     // Key-value pairs
    pub oids: HashSet<String>,                    // Array
    pub redirect_chain: Vec<String>,              // Ordered array
    pub technologies: Vec<String>,                // Array
    pub subject_alternative_names: Vec<String>,   // Array
    pub analytics_ids: Vec<AnalyticsId>,         // Array of structs
    pub geoip: Option<(String, GeoIpResult)>,    // Optional nested object
    pub structured_data: Option<StructuredData>, // Optional nested object
    pub social_media_links: Vec<SocialMediaLink>, // Array of structs
    pub security_warnings: Vec<SecurityWarning>,  // Array of enums
    pub whois: Option<WhoisResult>,              // Optional nested object
    pub partial_failures: Vec<UrlPartialFailureRecord>, // Array of structs
}
```

### Nested Structures

- **GeoIpResult**: Contains country, region, city, coordinates, ASN, etc.
- **StructuredData**: Contains JSON-LD, Open Graph, Twitter Cards (all nested)
- **AnalyticsId**: Contains provider and id
- **SocialMediaLink**: Contains platform, URL, identifier
- **WhoisResult**: Contains dates, registrar, registrant info
- **UrlPartialFailureRecord**: Contains error type, message, timestamp

## Serialization Format Comparison

### 1. JSONL (JSON Lines) - **For Programmatic Access**

**Pros:**
- Native support for nested structures
- One record per line (streamable)
- Human-readable
- Widely supported by data tools (pandas, jq, etc.)
- No data loss or duplication
- Easy to parse incrementally

**Cons:**
- **Excel/Sheets don't handle nested JSON well** - requires Power Query or conversion
- Larger file size than binary formats
- Not as efficient for analytics as Parquet
- Requires denormalization (joining all database tables)

**Excel Compatibility:**
- Excel can import JSON, but nested structures become complex
- Would need Power Query to flatten, or convert to CSV first
- **Not ideal for Excel users** - CSV is better for that use case

**Example Structure:**
```json
{
  "schema_version": "1.0",
  "run_id": "run_1234567890",
  "url": {
    "initial": "https://example.com",
    "final": "https://www.example.com",
    "domain": "example.com",
    "final_domain": "www.example.com",
    "ip_address": "93.184.216.34",
    "reverse_dns": "one.one.one.one"
  },
  "http": {
    "status": 200,
    "status_description": "OK",
    "response_time_ms": 184.5,
    "headers": {
      "server": "nginx/1.18.0",
      "content-type": "text/html"
    },
    "security_headers": {
      "strict-transport-security": "max-age=31536000"
    }
  },
  "html": {
    "title": "Example Domain",
    "keywords": ["example", "domain"],
    "description": "Example domain description",
    "is_mobile_friendly": true
  },
  "redirects": [
    {"sequence": 1, "url": "https://example.com", "status": 301},
    {"sequence": 2, "url": "https://www.example.com", "status": 200}
  ],
  "tls": {
    "version": "TLSv1.3",
    "certificate": {
      "subject": "CN=example.com",
      "issuer": "CN=Let's Encrypt",
      "valid_from": "2024-01-01T00:00:00Z",
      "valid_to": "2024-04-01T00:00:00Z",
      "oids": ["1.3.6.1.4.1.311"],
      "subject_alternative_names": ["example.com", "www.example.com"]
    },
    "cipher_suite": "TLS_AES_256_GCM_SHA384",
    "key_algorithm": "RSA"
  },
  "dns": {
    "nameservers": ["ns1.example.com", "ns2.example.com"],
    "txt_records": [
      {"value": "v=spf1 include:_spf.example.com", "type": "SPF"},
      {"value": "v=DMARC1; p=reject", "type": "DMARC"}
    ],
    "mx_records": [
      {"priority": 10, "host": "mail.example.com"}
    ]
  },
  "technologies": [
    {"name": "nginx", "category": "Web Servers"},
    {"name": "PHP", "category": "Programming Languages"}
  ],
  "analytics": [
    {"provider": "Google Analytics", "id": "UA-123456-1"}
  ],
  "geoip": {
    "ip_address": "93.184.216.34",
    "country": {
      "code": "US",
      "name": "United States"
    },
    "region": {
      "code": "MA",
      "name": "Massachusetts"
    },
    "city": "Boston",
    "location": {
      "latitude": 42.3601,
      "longitude": -71.0589,
      "timezone": "America/New_York"
    },
    "asn": {
      "number": 15133,
      "organization": "Edgecast Inc."
    }
  },
  "whois": {
    "creation_date": "2000-01-01T00:00:00Z",
    "expiration_date": "2025-01-01T00:00:00Z",
    "updated_date": "2024-01-01T00:00:00Z",
    "registrar": "Example Registrar",
    "registrant_country": "US",
    "registrant_org": "Example Organization",
    "status": "clientTransferProhibited",
    "nameservers": ["ns1.example.com", "ns2.example.com"]
  },
  "structured_data": {
    "json_ld": [
      {"@type": "Organization", "name": "Example Corp"}
    ],
    "open_graph": {
      "og:title": "Example Domain",
      "og:description": "Example description"
    },
    "twitter_cards": {
      "twitter:card": "summary",
      "twitter:title": "Example Domain"
    }
  },
  "social_media": [
    {"platform": "LinkedIn", "url": "https://linkedin.com/company/example", "identifier": "example"}
  ],
  "security_warnings": ["NoHttps", "WeakTls"],
  "partial_failures": [
    {"error_type": "DnsError", "error_message": "DNS lookup failed", "timestamp": 1234567890}
  ],
  "timestamp": 1234567890,
  "run_id": "run_1234567890"
}
```

### 2. CSV - **RECOMMENDED for Excel/Sheets Users**

**Pros:**
- **Excel/Google Sheets native support** - opens directly
- Universal compatibility (most BI tools)
- Human-readable
- Small file size
- Familiar format for non-technical users
- No conversion needed

**Cons:**
- **Cannot preserve nested structure** - requires flattening
- Arrays must be serialized (comma-separated or JSON strings)
- Nested objects must be flattened (prefix-based columns)
- Some relationships lost (e.g., redirect sequence, technology categories)
- Requires denormalization (joining all database tables) - same complexity as JSONL

**Use Cases:**
- Excel/Sheets analysis (primary use case)
- Quick reporting
- Sharing with non-technical users
- When you only need top-level fields
- When nested data isn't critical

**Flattening Strategy:**
- Nested objects → prefixed columns (`geoip_country_code`, `geoip_city`, `tls_cert_subject`)
- Arrays → comma-separated strings (`technologies: "nginx,PHP"`)
- Counts for arrays (`redirect_count: 2`, `technology_count: 2`)
- One row per URL (no duplication)

**Example:**
```csv
url,status,technologies,redirect_count,geoip_country_code,geoip_city,tls_version
https://example.com,200,"nginx,PHP",2,US,Boston,TLSv1.3
```

**Recommendation**: **CSV is more valuable than initially thought** - Excel users need it. Provide as `--format csv` with clear documentation about what's included/excluded.

### 3. Parquet - **RECOMMENDED for analytics**

**Pros:**
- Native support for nested structures
- Columnar format (efficient for analytics)
- Compression (smaller file size)
- Type preservation
- Fast querying with tools like DuckDB, Polars, pandas

**Cons:**
- Requires additional dependency (`parquet` crate)
- Less human-readable
- Not as universal as JSON/CSV

**Structure**: Same nested structure as JSONL, but stored in columnar format.

**Recommendation**: Provide as `--format parquet` option for data science workflows.

## Recommended Implementation Strategy

### User Personas and Format Selection

1. **Business Users (Non-Technical)** → CSV
   - Need Excel/Sheets compatibility
   - Won't run CLI themselves, but tech team will export for them
   - CSV export empowers tech users to satisfy non-tech stakeholders easily

2. **Developers/Data Engineers** → JSONL
   - Programmatic access (pandas, jq, data pipelines)
   - Saves them from writing SQL to assemble data
   - Preserves all nested data

3. **Data Scientists (Large-Scale)** → Parquet
   - Millions of records, data lake environments
   - Performance and compression matter
   - Advanced analytics workflows

4. **Power Users (Complex Queries)** → SQLite
   - Use the database directly with SQL
   - Maximum flexibility for custom analysis
   - No denormalization needed

**All export formats require denormalization** - joining all the normalized tables into a single record per URL. The complexity is the same for CSV, JSONL, and Parquet.

### Phase 1: CSV Export (HIGH PRIORITY)

**Rationale**: Excel doesn't handle nested JSON well. Business users need CSV, and tech users need an easy way to export for them.

1. **Flattened CSV Export**
   - Query all normalized tables and join (denormalization)
   - Flatten nested objects with prefixes (`geoip_country_code`, `geoip_city`)
   - Arrays as comma-separated strings (`technologies: "nginx,PHP"`)
   - Include counts for arrays (`redirect_count`, `technology_count`)
   - One row per URL (no duplication)
   - **Document what's included/excluded** - CSV is a simplified view

2. **Fields to Include in CSV:**
   - Core: `url`, `status`, `status_description`, `response_time_ms`
   - Redirects: `redirect_count`, `final_url` (last redirect)
   - Technologies: `technologies` (comma-separated), `technology_count`
   - TLS: `tls_version`, `ssl_cert_subject`, `ssl_cert_issuer`, `ssl_cert_valid_to`
   - DNS: `nameserver_count`, `txt_record_count`, `mx_record_count`
   - GeoIP: `geoip_country_code`, `geoip_city`, `geoip_asn`
   - WHOIS: `whois_registrar`, `whois_creation_date`, `whois_expiration_date`
   - HTML: `title`, `description`, `is_mobile_friendly`
   - Timestamps: `timestamp`, `run_id`

3. **Fields to Exclude from CSV:**
   - Full structured data (too complex to flatten)
   - Complete redirect chains (just count and final URL)
   - All DNS record details (just counts)
   - Full security headers (maybe just key ones)
   - Partial failures (too detailed for CSV)

4. **CLI Command**
   ```bash
   domain_status export --db domain_status.db --format csv --output results.csv
   ```

5. **Streaming Implementation**
   - Use cursor-based queries to avoid loading all data in memory
   - Process one URL at a time: query → join → flatten → write CSV line
   - Handle millions of records efficiently

### Phase 2: JSONL Export (MEDIUM PRIORITY)

**Rationale**: Developers and data engineers need programmatic access without writing SQL.

1. **Create `src/export/` module**
   - `mod.rs` - Public API
   - `jsonl.rs` - JSONL serialization
   - `types.rs` - Export record types

2. **Export Record Type**
   ```rust
   pub struct ExportRecord {
       pub schema_version: String,
       pub run_id: String,
       pub url: UrlInfo,
       pub http: HttpInfo,
       pub html: HtmlInfo,
       pub redirects: Vec<RedirectInfo>,
       pub tls: Option<TlsInfo>,
       pub dns: Option<DnsInfo>,
       pub technologies: Vec<TechnologyInfo>,
       pub analytics: Vec<AnalyticsId>,
       pub geoip: Option<GeoIpInfo>,
       pub whois: Option<WhoisInfo>,
       pub structured_data: Option<StructuredDataInfo>,
       pub social_media: Vec<SocialMediaLink>,
       pub security_warnings: Vec<String>,
       pub partial_failures: Vec<PartialFailureInfo>,
       pub timestamp: i64,
   }
   ```

3. **Query and Transform**
   - Query database using existing storage module
   - Transform `BatchRecord`-like data into `ExportRecord`
   - Serialize to JSONL using `serde_json`

4. **CLI Command**
   ```bash
   domain_status export --db domain_status.db --format jsonl --output results.jsonl
   ```

### Phase 3: Parquet Export (LOWER PRIORITY)

**Rationale**: Advanced analytics at scale. Nice-to-have for data science workflows.

1. **Parquet Serialization**
   - Use `parquet` crate or `arrow` crate
   - Preserve nested structure (same as JSONL)
   - Support schema evolution
   - Columnar format for efficient analytics

2. **CLI Command**
   ```bash
   domain_status export --db domain_status.db --format parquet --output results.parquet
   ```

## Empty Arrays vs Nulls in JSON

**Important consideration**: JSON serialization needs to handle empty collections carefully.

**Options:**
1. **Always include arrays** (even if empty): `"technologies": []` vs `"technologies": null`
2. **Omit empty arrays**: Use `#[serde(skip_serializing_if = "Vec::is_empty")]`
3. **Use null for missing data**: `"geoip": null` vs `"geoip": {}`

**Recommendation**:
- Use `Option<T>` for truly optional data (GeoIP, WHOIS) → serialize as `null` if missing
- Use `Vec<T>` for collections → serialize as `[]` if empty (not null)
- Use `#[serde(skip_serializing_if)]` to omit empty arrays if desired (cleaner JSON)

**Example:**
```json
{
  "technologies": [],           // Empty array (not null)
  "redirects": [],              // Empty array (not null)
  "geoip": null,                // Null (optional, not present)
  "whois": null                 // Null (optional, not present)
}
```

vs (with skip_serializing_if):
```json
{
  // technologies omitted if empty
  // redirects omitted if empty
  "geoip": null,
  "whois": null
}
```

**My recommendation**: Include empty arrays as `[]` for consistency and to make it clear the field exists but is empty. Use `null` only for truly optional nested objects (GeoIP, WHOIS, structured_data).

## Schema Versioning

All export formats should include:
- `schema_version`: Semantic version (e.g., "1.0")
- Only additive changes in minor versions
- Breaking changes bump major version

## Implementation Notes

1. **Streaming**: JSONL can be streamed (one record at a time)
2. **Memory**: For large databases, use cursor-based iteration
3. **Filtering**: Support `--run-id`, `--domain`, `--status` filters
4. **Incremental**: Support `--since` timestamp for incremental exports

## Example Usage

```bash
# JSONL export (recommended for most use cases - preserves all nested data)
domain_status export --db domain_status.db --format jsonl > results.jsonl

# Parquet export (for analytics/data science - preserves all nested data, columnar format)
domain_status export --db domain_status.db --format parquet --output results.parquet

# Filtered export
domain_status export --db domain_status.db --format jsonl --run-id run_1234567890

# Incremental export
domain_status export --db domain_status.db --format jsonl --since 2024-01-01T00:00:00Z

# CSV export (optional, simplified view - only if implemented)
# domain_status export --db domain_status.db --format csv --simplified > results.csv
```

## Final Recommendation

### Implementation Priority

1. **CSV Export** - **HIGH PRIORITY**
   - Excel/Sheets users need this
   - Tech users need easy way to export for business stakeholders
   - Simpler than JSONL (no nested structure to serialize)
   - Same denormalization complexity as JSONL

2. **JSONL Export** - **MEDIUM PRIORITY**
   - Developers and data engineers need programmatic access
   - Saves them from writing SQL to assemble data
   - Preserves all nested data
   - Same denormalization complexity as CSV

3. **Parquet Export** - **LOWER PRIORITY**
   - Advanced analytics at scale
   - Nice-to-have for data science workflows
   - Can defer until after CSV/JSONL are done
   - More complex implementation (Arrow/Parquet libraries)

### Keep SQLite as Core Storage

- **Don't remove or change SQLite** - it remains valuable
- SQL queries are the best way to work with normalized data
- Export formats are complementary, not replacements
- Power users can continue using SQLite directly
- Document SQL query examples in `QUERIES.md`

### Key Insights from Analysis

1. **Excel compatibility is critical**: Excel doesn't handle nested JSON well, making CSV essential
2. **Business users won't run CLI**: But tech users will export CSV for them - this empowers tech users
3. **All formats require denormalization**: Same complexity for CSV, JSONL, and Parquet (joining all tables)
4. **Streaming is essential**: Must handle millions of domains without memory issues
5. **SQLite remains powerful**: For complex queries, SQL on the normalized database is best

### Documentation Requirements

For each export format, document:
- What fields are included/excluded (especially for CSV)
- Limitations (e.g., CSV is simplified view)
- Use cases and target audience
- How to handle large datasets (streaming, compression)
- Schema versioning approach
