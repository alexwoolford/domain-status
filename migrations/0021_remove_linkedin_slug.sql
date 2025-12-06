-- Remove linkedin_slug column from url_status table
-- This information is now captured in url_social_media_links table

-- Step 1: Create new table without linkedin_slug
CREATE TABLE IF NOT EXISTS url_status_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    final_domain TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    reverse_dns_name TEXT,
    status INTEGER NOT NULL,
    status_description TEXT NOT NULL,
    response_time NUMERIC(10,2) NOT NULL,
    title TEXT NOT NULL,
    keywords TEXT,
    description TEXT,
    tls_version TEXT,
    ssl_cert_subject TEXT,
    ssl_cert_issuer TEXT,
    ssl_cert_valid_from INTEGER,
    ssl_cert_valid_to INTEGER,
    is_mobile_friendly BOOLEAN NOT NULL DEFAULT 0,
    timestamp INTEGER NOT NULL,
    spf_record TEXT,
    dmarc_record TEXT,
    cipher_suite TEXT,
    key_algorithm TEXT,
    run_id TEXT,
    UNIQUE(final_domain, timestamp)
);

-- Step 2: Copy data from old table to new table (excluding linkedin_slug)
INSERT INTO url_status_new (
    id, domain, final_domain, ip_address, reverse_dns_name, status, status_description,
    response_time, title, keywords, description, tls_version, ssl_cert_subject,
    ssl_cert_issuer, ssl_cert_valid_from, ssl_cert_valid_to, is_mobile_friendly, timestamp,
    spf_record, dmarc_record, cipher_suite, key_algorithm, run_id
)
SELECT
    id, domain, final_domain, ip_address, reverse_dns_name, status, status_description,
    response_time, title, keywords, description, tls_version, ssl_cert_subject,
    ssl_cert_issuer, ssl_cert_valid_from, ssl_cert_valid_to, is_mobile_friendly, timestamp,
    spf_record, dmarc_record, cipher_suite, key_algorithm, run_id
FROM url_status;

-- Step 3: Drop old table
DROP TABLE url_status;

-- Step 4: Rename new table to original name
ALTER TABLE url_status_new RENAME TO url_status;

-- Step 5: Recreate indexes (they were dropped with the old table)
CREATE INDEX IF NOT EXISTS idx_url_status_final_domain_timestamp
    ON url_status(final_domain, timestamp);
CREATE INDEX IF NOT EXISTS idx_url_status_run_id_timestamp
    ON url_status(run_id, timestamp);
