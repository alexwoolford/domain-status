-- Normalize security headers into a separate table
-- Security headers are key-value pairs that should be stored in a normalized table
-- instead of as JSON in the url_status table

-- Step 1: Create child table for security headers
CREATE TABLE IF NOT EXISTS url_security_headers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    header_name TEXT NOT NULL,
    header_value TEXT NOT NULL,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE (url_status_id, header_name)
);

CREATE INDEX IF NOT EXISTS idx_url_security_headers_name 
    ON url_security_headers(header_name);

CREATE INDEX IF NOT EXISTS idx_url_security_headers_status_id 
    ON url_security_headers(url_status_id);

-- Step 2: Migrate existing data from JSON column to normalized table
-- This extracts key-value pairs from the JSON security_headers column
INSERT INTO url_security_headers (url_status_id, header_name, header_value)
SELECT 
    us.id,
    json_each.key,
    json_each.value
FROM url_status us,
     json_each(us.security_headers)
WHERE us.security_headers IS NOT NULL 
  AND us.security_headers != '{}'
  AND us.security_headers != '';

-- Step 3: Remove security_headers column from url_status
-- SQLite doesn't support DROP COLUMN directly, so we recreate the table
CREATE TABLE IF NOT EXISTS url_status_new (
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL,
    final_domain TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    reverse_dns_name TEXT,
    status INTEGER NOT NULL,
    status_description TEXT NOT NULL,
    response_time NUMERIC(10, 2),
    title TEXT NOT NULL,
    keywords TEXT,
    description TEXT,
    linkedin_slug TEXT,
    -- Removed: security_headers (use url_security_headers table)
    tls_version TEXT,
    ssl_cert_subject TEXT,
    ssl_cert_issuer TEXT,
    ssl_cert_valid_from INTEGER,
    ssl_cert_valid_to INTEGER,
    oids TEXT,
    is_mobile_friendly BOOLEAN,
    timestamp INTEGER NOT NULL,
    redirect_chain TEXT,
    spf_record TEXT,
    dmarc_record TEXT,
    cipher_suite TEXT,
    key_algorithm TEXT,
    run_id TEXT,
    UNIQUE (final_domain, timestamp)
);

-- Step 4: Copy data (excluding security_headers column)
INSERT INTO url_status_new (
    id, domain, final_domain, ip_address, reverse_dns_name,
    status, status_description, response_time, title, keywords, description,
    linkedin_slug, tls_version, ssl_cert_subject, ssl_cert_issuer,
    ssl_cert_valid_from, ssl_cert_valid_to, oids, is_mobile_friendly,
    timestamp, redirect_chain, spf_record, dmarc_record, cipher_suite,
    key_algorithm, run_id
)
SELECT 
    id, domain, final_domain, ip_address, reverse_dns_name,
    status, status_description, response_time, title, keywords, description,
    linkedin_slug, tls_version, ssl_cert_subject, ssl_cert_issuer,
    ssl_cert_valid_from, ssl_cert_valid_to, oids, is_mobile_friendly,
    timestamp, redirect_chain, spf_record, dmarc_record, cipher_suite,
    key_algorithm, run_id
FROM url_status;

-- Step 5: Drop old table and rename new one
DROP TABLE url_status;

-- Step 6: Rename new table to original name
ALTER TABLE url_status_new RENAME TO url_status;

-- Step 7: Recreate indexes
CREATE INDEX IF NOT EXISTS idx_url_status_domain ON url_status(domain);
CREATE INDEX IF NOT EXISTS idx_url_status_final_domain ON url_status(final_domain);
CREATE INDEX IF NOT EXISTS idx_url_status_timestamp ON url_status(timestamp);
CREATE INDEX IF NOT EXISTS idx_url_status_run_id_timestamp ON url_status(run_id, timestamp);

-- Note: The normalized child tables (url_technologies, url_nameservers, url_txt_records,
-- url_mx_records, url_security_headers) already exist and contain the data. The foreign key
-- constraints will remain valid because we preserved the `id` column (PRIMARY KEY) in the new table.

