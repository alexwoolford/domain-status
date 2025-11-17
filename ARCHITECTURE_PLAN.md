# Architecture Improvements - Implementation Plan

## 1. Normalize Multi-Valued Fields (Child Tables)

### Current State
- `technologies` stored as JSON string: `["WordPress", "PHP", "MySQL"]`
- `nameservers` stored as JSON string: `["ns1.example.com", "ns2.example.com"]`
- `txt_records` stored as JSON string: `["v=spf1 ...", "google-site-verification=..."]`
- `mx_records` stored as JSON string: `["10 mail.example.com", "20 mail2.example.com"]`

### New Schema Design

```sql
-- Main table gets run_id for time-series
ALTER TABLE url_status ADD COLUMN run_id TEXT;

-- Child tables for normalized relationships
CREATE TABLE IF NOT EXISTS url_technologies (
    id INTEGER PRIMARY KEY,
    url_status_id INTEGER NOT NULL,
    technology_name TEXT NOT NULL,
    technology_category TEXT,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, technology_name)
);

CREATE TABLE IF NOT EXISTS url_nameservers (
    id INTEGER PRIMARY KEY,
    url_status_id INTEGER NOT NULL,
    nameserver TEXT NOT NULL,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, nameserver)
);

CREATE TABLE IF NOT EXISTS url_txt_records (
    id INTEGER PRIMARY KEY,
    url_status_id INTEGER NOT NULL,
    txt_record TEXT NOT NULL,
    record_type TEXT, -- 'SPF', 'DMARC', 'VERIFICATION', 'OTHER'
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS url_mx_records (
    id INTEGER PRIMARY KEY,
    url_status_id INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    mail_exchange TEXT NOT NULL,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, priority, mail_exchange)
);
```

### Benefits
- **Queryable**: `SELECT * FROM url_technologies WHERE technology_name = 'WordPress'`
- **Joinable**: `SELECT u.domain, t.technology_name FROM url_status u JOIN url_technologies t ON u.id = t.url_status_id`
- **Indexable**: Can create indexes on `technology_name`, `nameserver`, etc.
- **No JSON parsing**: Direct SQL queries, faster analytics

### Implementation Strategy
1. **Keep wide table for convenience**: Don't remove `technologies`, `nameservers`, etc. columns yet
2. **Dual-write**: Insert into both wide table (JSON) AND child tables (normalized)
3. **Migration path**: Existing data can be backfilled from JSON columns
4. **Query flexibility**: Users can query either format

---

## 2. Add run_id for Time-Series Comparison

### Migration
```sql
-- Add run_id column
ALTER TABLE url_status ADD COLUMN run_id TEXT;

-- Create index for time-series queries
CREATE INDEX IF NOT EXISTS idx_url_status_run_id_timestamp 
    ON url_status(run_id, timestamp);

-- Generate run_id on insert (UUID or timestamp-based)
```

### Usage Pattern
```rust
// Generate run_id at start of run
let run_id = format!("run_{}", chrono::Utc::now().timestamp());

// Store with every record
UrlRecord {
    // ... existing fields ...
    run_id: Some(run_id.clone()),
}

// Query: "What changed since last week?"
SELECT * FROM url_status 
WHERE domain = 'example.com' 
  AND run_id IN (
    SELECT run_id FROM url_status 
    WHERE timestamp > (SELECT MAX(timestamp) - 604800000 FROM url_status)
    GROUP BY run_id
  )
ORDER BY timestamp DESC;
```

---

## 3. Break into Modules

### Current Structure
```
src/
├── main.rs              # CLI, orchestration
├── config.rs            # Constants
├── database.rs          # DB operations
├── domain.rs            # Domain extraction
├── html.rs              # HTML parsing
├── dns.rs               # DNS lookups
├── tls.rs               # TLS/certificate
├── http.rs              # HTTP client
├── tech_detection.rs    # Wappalyzer
├── error_handling.rs    # Error types
├── initialization.rs    # Setup
└── utils.rs             # process_url, retry logic
```

### Proposed Structure
```
src/
├── main.rs                    # CLI, orchestration
├── config.rs                  # Constants
│
├── fetch/                     # HTTP fetching module
│   ├── mod.rs
│   ├── client.rs              # reqwest client setup
│   ├── redirect.rs            # Redirect handling
│   └── response.rs            # Response processing
│
├── tls/                       # TLS module
│   ├── mod.rs
│   ├── connector.rs           # TLS connection
│   └── certificate.rs         # Cert parsing/extraction
│
├── dns/                       # DNS module
│   ├── mod.rs
│   ├── resolver.rs            # DNS resolver setup
│   ├── records.rs             # NS, MX, TXT lookups
│   └── spf_dmarc.rs           # SPF/DMARC parsing
│
├── parse/                     # Parsing module
│   ├── mod.rs
│   ├── html.rs                # HTML extraction (title, meta, etc.)
│   ├── headers.rs             # Security headers parsing
│   └── vendors.rs             # TXT vendor normalization
│
├── fingerprint/               # Technology detection
│   ├── mod.rs
│   ├── wappalyzer.rs          # Rules loading/matching
│   └── inference.rs           # CDN/WAF inference
│
├── derive/                    # Feature derivation
│   ├── mod.rs
│   ├── posture.rs             # Security posture score
│   ├── certificate.rs         # Cert-derived features (EV/OV/DV, expiry)
│   ├── redirect.rs            # Redirect analytics
│   └── vendor.rs              # Vendor mapping
│
├── storage/                   # Database module
│   ├── mod.rs
│   ├── pool.rs                # Connection pool
│   ├── models.rs              # UrlRecord, etc.
│   ├── insert.rs              # Insert operations
│   ├── query.rs               # Query operations
│   └── migrations.rs          # Migration helpers
│
├── error_handling.rs          # Error types
└── utils.rs                   # Shared utilities
```

### Module Example: `src/fetch/mod.rs`
```rust
pub mod client;
pub mod redirect;
pub mod response;

pub use client::create_http_client;
pub use redirect::follow_redirects;
pub use response::handle_response;
```

### Module Example: `src/derive/mod.rs`
```rust
pub mod posture;
pub mod certificate;
pub mod redirect;
pub mod vendor;

pub use posture::SecurityPosture;
pub use certificate::CertificateFeatures;
pub use redirect::RedirectAnalytics;
pub use vendor::VendorMap;
```

---

## Implementation Order

### Phase 1: Add run_id (Simple, High Value)
1. Create migration `0009_add_run_id.sql`
2. Add `run_id` field to `UrlRecord`
3. Generate run_id in `main.rs` at start
4. Pass run_id through to insert

### Phase 2: Normalize Tables (Medium Complexity)
1. Create migration `0010_normalize_tables.sql` (child tables)
2. Create helper functions to parse JSON → Vec<String>
3. Update `insert_url_record` to dual-write (wide + normalized)
4. Add helper queries for child tables

### Phase 3: Module Reorganization (Refactoring)
1. Create new module directories
2. Move code incrementally (one module at a time)
3. Update imports
4. Test after each move

---

## Query Examples After Normalization

### Find all domains using WordPress
```sql
SELECT DISTINCT u.domain 
FROM url_status u
JOIN url_technologies t ON u.id = t.url_status_id
WHERE t.technology_name = 'WordPress';
```

### Find domains with Cloudflare nameservers
```sql
SELECT DISTINCT u.domain
FROM url_status u
JOIN url_nameservers n ON u.id = n.url_status_id
WHERE n.nameserver LIKE '%.cloudflare.com';
```

### Compare technologies between runs
```sql
SELECT 
    u1.run_id as run1,
    u2.run_id as run2,
    t1.technology_name,
    CASE 
        WHEN t2.technology_name IS NULL THEN 'added'
        ELSE 'unchanged'
    END as change
FROM url_status u1
JOIN url_technologies t1 ON u1.id = t1.url_status_id
LEFT JOIN url_status u2 ON u1.domain = u2.domain AND u2.run_id = 'run_previous'
LEFT JOIN url_technologies t2 ON u2.id = t2.url_status_id AND t1.technology_name = t2.technology_name
WHERE u1.run_id = 'run_current' AND t2.technology_name IS NULL;
```

