# Architecture Implementation - Code Examples

## Example 1: Insert with Normalized Tables

### Before (Current)
```rust
// src/database.rs
pub async fn insert_url_record(pool: &SqlitePool, record: &UrlRecord) -> Result<(), DatabaseError> {
    sqlx::query(
        "INSERT INTO url_status (..., technologies, nameservers, txt_records, mx_records) 
         VALUES (..., ?, ?, ?, ?)"
    )
    .bind(&record.technologies)  // JSON string: ["WordPress", "PHP"]
    .bind(&record.nameservers)     // JSON string: ["ns1.example.com"]
    .bind(&record.txt_records)     // JSON string: ["v=spf1 ..."]
    .bind(&record.mx_records)      // JSON string: ["10 mail.example.com"]
    .execute(pool)
    .await?;
    Ok(())
}
```

### After (Normalized)
```rust
// src/storage/insert.rs
pub async fn insert_url_record(
    pool: &SqlitePool, 
    record: &UrlRecord
) -> Result<i64, DatabaseError> {
    // Start transaction
    let mut tx = pool.begin().await?;
    
    // 1. Insert main record, get back the ID
    let url_status_id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO url_status (..., technologies, nameservers, txt_records, mx_records, run_id)
         VALUES (..., ?, ?, ?, ?, ?)
         RETURNING id"
    )
    .bind(&record.technologies)  // Keep JSON for backward compatibility
    .bind(&record.nameservers)
    .bind(&record.txt_records)
    .bind(&record.mx_records)
    .bind(&record.run_id)
    .fetch_one(&mut *tx)
    .await?;
    
    // 2. Insert normalized technologies
    if let Some(techs) = parse_json_array(&record.technologies) {
        for tech in techs {
            sqlx::query(
                "INSERT INTO url_technologies (url_status_id, technology_name)
                 VALUES (?, ?)
                 ON CONFLICT(url_status_id, technology_name) DO NOTHING"
            )
            .bind(url_status_id)
            .bind(tech)
            .execute(&mut *tx)
            .await?;
        }
    }
    
    // 3. Insert normalized nameservers
    if let Some(ns) = parse_json_array(&record.nameservers) {
        for nameserver in ns {
            sqlx::query(
                "INSERT INTO url_nameservers (url_status_id, nameserver)
                 VALUES (?, ?)
                 ON CONFLICT(url_status_id, nameserver) DO NOTHING"
            )
            .bind(url_status_id)
            .bind(nameserver)
            .execute(&mut *tx)
            .await?;
        }
    }
    
    // 4. Insert normalized TXT records (with type detection)
    if let Some(txts) = parse_json_array(&record.txt_records) {
        for txt in txts {
            let record_type = detect_txt_type(&txt); // "SPF", "DMARC", "VERIFICATION", etc.
            sqlx::query(
                "INSERT INTO url_txt_records (url_status_id, txt_record, record_type)
                 VALUES (?, ?, ?)"
            )
            .bind(url_status_id)
            .bind(txt)
            .bind(record_type)
            .execute(&mut *tx)
            .await?;
        }
    }
    
    // 5. Insert normalized MX records (parse priority)
    if let Some(mx) = parse_json_array(&record.mx_records) {
        for mx_record in mx {
            if let Some((priority, host)) = parse_mx_record(&mx_record) {
                sqlx::query(
                    "INSERT INTO url_mx_records (url_status_id, priority, mail_exchange)
                     VALUES (?, ?, ?)
                     ON CONFLICT(url_status_id, priority, mail_exchange) DO NOTHING"
                )
                .bind(url_status_id)
                .bind(priority)
                .bind(host)
                .execute(&mut *tx)
                .await?;
            }
        }
    }
    
    // Commit transaction
    tx.commit().await?;
    Ok(url_status_id)
}

// Helper: Parse JSON array string to Vec<String>
fn parse_json_array(json_str: &Option<String>) -> Option<Vec<String>> {
    json_str.as_ref()?;
    serde_json::from_str(json_str.as_ref().unwrap()).ok()
}

// Helper: Parse MX record "10 mail.example.com" -> (10, "mail.example.com")
fn parse_mx_record(mx: &str) -> Option<(i32, String)> {
    let parts: Vec<&str> = mx.split_whitespace().collect();
    if parts.len() >= 2 {
        parts[0].parse::<i32>().ok().map(|p| (p, parts[1].to_string()))
    } else {
        None
    }
}

// Helper: Detect TXT record type
fn detect_txt_type(txt: &str) -> Option<String> {
    if txt.starts_with("v=spf1") {
        Some("SPF".to_string())
    } else if txt.starts_with("v=DMARC1") {
        Some("DMARC".to_string())
    } else if txt.contains("google-site-verification") {
        Some("VERIFICATION".to_string())
    } else {
        Some("OTHER".to_string())
    }
}
```

---

## Example 2: Module Structure

### `src/fetch/mod.rs`
```rust
pub mod client;
pub mod redirect;
pub mod response;

pub use client::create_http_client;
pub use redirect::follow_redirects;
pub use response::handle_response;
```

### `src/fetch/client.rs`
```rust
use reqwest::Client;

pub fn create_http_client() -> Result<Client, anyhow::Error> {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(Into::into)
}
```

### `src/derive/mod.rs`
```rust
pub mod posture;
pub mod certificate;
pub mod redirect;
pub mod vendor;

pub use posture::{SecurityPosture, calculate_posture_score};
pub use certificate::{CertificateFeatures, extract_cert_features};
pub use redirect::{RedirectAnalytics, analyze_redirects};
pub use vendor::{VendorMap, normalize_vendors};
```

### `src/derive/posture.rs`
```rust
use crate::models::UrlRecord;

pub struct SecurityPosture {
    pub has_hsts: bool,
    pub hsts_max_age: Option<u64>,
    pub hsts_subdomains: bool,
    pub has_csp: bool,
    pub csp_allows_unsafe_inline: bool,
    pub has_xfo: bool,
    pub has_xcto: bool,
    pub has_referrer_policy: bool,
}

pub fn calculate_posture_score(posture: &SecurityPosture) -> u8 {
    let mut score = 0;
    if posture.has_hsts { score += 20; }
    if posture.hsts_max_age.unwrap_or(0) >= 31536000 { score += 10; } // 1 year
    if posture.has_csp { score += 15; }
    if !posture.csp_allows_unsafe_inline { score += 10; }
    if posture.has_xfo { score += 15; }
    if posture.has_xcto { score += 15; }
    if posture.has_referrer_policy { score += 15; }
    score
}

pub fn extract_posture(record: &UrlRecord) -> SecurityPosture {
    // Parse security_headers JSON and extract flags
    // Implementation here...
}
```

---

## Example 3: Using run_id

### `src/main.rs` (start of run)
```rust
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Generate run_id at start
    let run_id = format!("run_{}", Uuid::new_v4());
    log::info!("Starting run: {}", run_id);
    
    // Pass run_id to process_url
    for url in urls {
        process_url(url, &run_id, pool.clone()).await?;
    }
    
    log::info!("Completed run: {}", run_id);
    Ok(())
}
```

### `src/utils.rs` (process_url)
```rust
pub async fn process_url(
    url: Arc<String>,
    run_id: &str,  // Add run_id parameter
    pool: Arc<SqlitePool>,
    // ... other params
) -> Result<UrlRecord, anyhow::Error> {
    // ... existing logic ...
    
    let record = UrlRecord {
        // ... existing fields ...
        run_id: Some(run_id.to_string()),
    };
    
    database::insert_url_record(&pool, &record).await?;
    Ok(record)
}
```

---

## Example 4: Query Normalized Data

### `src/storage/query.rs`
```rust
use sqlx::SqlitePool;

// Find all domains using a specific technology
pub async fn find_domains_with_technology(
    pool: &SqlitePool,
    technology: &str,
) -> Result<Vec<String>, DatabaseError> {
    let domains = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT u.domain
         FROM url_status u
         JOIN url_technologies t ON u.id = t.url_status_id
         WHERE t.technology_name = ?
         ORDER BY u.timestamp DESC"
    )
    .bind(technology)
    .fetch_all(pool)
    .await?;
    
    Ok(domains)
}

// Get technology stack for a domain (latest run)
pub async fn get_technology_stack(
    pool: &SqlitePool,
    domain: &str,
) -> Result<Vec<String>, DatabaseError> {
    let technologies = sqlx::query_scalar::<_, String>(
        "SELECT t.technology_name
         FROM url_status u
         JOIN url_technologies t ON u.id = t.url_status_id
         WHERE u.domain = ?
           AND u.timestamp = (SELECT MAX(timestamp) FROM url_status WHERE domain = ?)
         ORDER BY t.technology_name"
    )
    .bind(domain)
    .bind(domain)
    .fetch_all(pool)
    .await?;
    
    Ok(technologies)
}

// Compare technologies between two runs
pub async fn compare_runs(
    pool: &SqlitePool,
    domain: &str,
    run1: &str,
    run2: &str,
) -> Result<RunComparison, DatabaseError> {
    // Technologies added
    let added = sqlx::query_scalar::<_, String>(
        "SELECT t1.technology_name
         FROM url_status u1
         JOIN url_technologies t1 ON u1.id = t1.url_status_id
         LEFT JOIN url_status u2 ON u1.domain = u2.domain AND u2.run_id = ?
         LEFT JOIN url_technologies t2 ON u2.id = t2.url_status_id 
             AND t1.technology_name = t2.technology_name
         WHERE u1.domain = ? AND u1.run_id = ? AND t2.technology_name IS NULL"
    )
    .bind(run2)
    .bind(domain)
    .bind(run1)
    .fetch_all(pool)
    .await?;
    
    // Technologies removed
    let removed = sqlx::query_scalar::<_, String>(
        "SELECT t2.technology_name
         FROM url_status u2
         JOIN url_technologies t2 ON u2.id = t2.url_status_id
         LEFT JOIN url_status u1 ON u2.domain = u1.domain AND u1.run_id = ?
         LEFT JOIN url_technologies t1 ON u1.id = t1.url_status_id 
             AND t2.technology_name = t1.technology_name
         WHERE u2.domain = ? AND u2.run_id = ? AND t1.technology_name IS NULL"
    )
    .bind(run1)
    .bind(domain)
    .bind(run2)
    .fetch_all(pool)
    .await?;
    
    Ok(RunComparison { added, removed })
}
```

---

## Migration File Example

### `migrations/0009_add_run_id.sql`
```sql
-- Add run_id column for time-series tracking
ALTER TABLE url_status ADD COLUMN run_id TEXT;

-- Create index for efficient run-based queries
CREATE INDEX IF NOT EXISTS idx_url_status_run_id_timestamp 
    ON url_status(run_id, timestamp);
```

### `migrations/0010_normalize_tables.sql`
```sql
-- Create child tables for normalized relationships

CREATE TABLE IF NOT EXISTS url_technologies (
    id INTEGER PRIMARY KEY,
    url_status_id INTEGER NOT NULL,
    technology_name TEXT NOT NULL,
    technology_category TEXT,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, technology_name)
);

CREATE INDEX IF NOT EXISTS idx_url_technologies_name 
    ON url_technologies(technology_name);

CREATE INDEX IF NOT EXISTS idx_url_technologies_status_id 
    ON url_technologies(url_status_id);

CREATE TABLE IF NOT EXISTS url_nameservers (
    id INTEGER PRIMARY KEY,
    url_status_id INTEGER NOT NULL,
    nameserver TEXT NOT NULL,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, nameserver)
);

CREATE INDEX IF NOT EXISTS idx_url_nameservers_nameserver 
    ON url_nameservers(nameserver);

CREATE TABLE IF NOT EXISTS url_txt_records (
    id INTEGER PRIMARY KEY,
    url_status_id INTEGER NOT NULL,
    txt_record TEXT NOT NULL,
    record_type TEXT, -- 'SPF', 'DMARC', 'VERIFICATION', 'OTHER'
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_url_txt_records_type 
    ON url_txt_records(record_type);

CREATE TABLE IF NOT EXISTS url_mx_records (
    id INTEGER PRIMARY KEY,
    url_status_id INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    mail_exchange TEXT NOT NULL,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, priority, mail_exchange)
);

CREATE INDEX IF NOT EXISTS idx_url_mx_records_exchange 
    ON url_mx_records(mail_exchange);
```

