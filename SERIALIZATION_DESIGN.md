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

### 1. JSONL (JSON Lines) - **RECOMMENDED**

**Pros:**
- Native support for nested structures
- One record per line (streamable)
- Human-readable
- Widely supported (pandas, jq, etc.)
- No data loss or duplication
- Easy to parse incrementally

**Cons:**
- Larger file size than binary formats
- Not as efficient for analytics as Parquet

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

### 2. CSV - **NOT RECOMMENDED for full export**

**Pros:**
- Universal compatibility (Excel, Google Sheets)
- Human-readable
- Small file size

**Cons:**
- Requires flattening nested data (data loss or duplication)
- Multiple strategies needed:
  - **Strategy A**: Separate files (urls.csv, redirects.csv, technologies.csv) - requires joins
  - **Strategy B**: Denormalized (one row per URL, arrays as JSON strings) - loses structure
  - **Strategy C**: Repeated rows (one row per URL+technology combination) - data duplication

**Example (Strategy B - Denormalized):**
```csv
url,status,technologies_json,redirects_json,geoip_country
https://example.com,200,"[""nginx"",""PHP""]","[""https://example.com"",""https://www.example.com""]","US"
```

**Recommendation**: Only provide CSV for simplified/flattened views (e.g., `--format csv --flatten`)

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

### Phase 1: JSONL Export (High Priority)

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

### Phase 2: CSV Export (Simplified View)

1. **Flattened CSV Export**
   - Only top-level fields
   - Arrays as JSON strings or comma-separated
   - Nested objects flattened with prefixes (e.g., `geoip_country_code`, `geoip_city`)

2. **CLI Command**
   ```bash
   domain_status export --db domain_status.db --format csv --flatten --output results.csv
   ```

### Phase 3: Parquet Export (Analytics)

1. **Parquet Serialization**
   - Use `parquet` crate or `arrow` crate
   - Preserve nested structure
   - Support schema evolution

2. **CLI Command**
   ```bash
   domain_status export --db domain_status.db --format parquet --output results.parquet
   ```

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
# JSONL export (recommended for most use cases)
domain_status export --db domain_status.db --format jsonl > results.jsonl

# CSV export (simplified, flattened)
domain_status export --db domain_status.db --format csv --flatten > results.csv

# Parquet export (for analytics)
domain_status export --db domain_status.db --format parquet --output results.parquet

# Filtered export
domain_status export --db domain_status.db --format jsonl --run-id run_1234567890

# Incremental export
domain_status export --db domain_status.db --format jsonl --since 2024-01-01T00:00:00Z
```
