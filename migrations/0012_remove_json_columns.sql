-- Remove redundant JSON columns from url_status table
-- These columns duplicate data that is now stored in normalized child tables:
-- - technologies -> url_technologies
-- - nameservers -> url_nameservers
-- - txt_records -> url_txt_records
-- - mx_records -> url_mx_records
--
-- This migration removes the JSON columns to eliminate data duplication
-- and establish a single source of truth in the normalized tables.
--
-- Note: SQLite doesn't support DROP COLUMN directly, so we recreate the table

-- Step 1: Create new table without JSON columns
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
    security_headers TEXT NOT NULL,
    tls_version TEXT,
    ssl_cert_subject TEXT,
    ssl_cert_issuer TEXT,
    ssl_cert_valid_from INTEGER,
    ssl_cert_valid_to INTEGER,
    oids TEXT,
    is_mobile_friendly BOOLEAN,
    timestamp INTEGER NOT NULL,
    redirect_chain TEXT,
    -- Removed: technologies (use url_technologies table)
    -- Removed: nameservers (use url_nameservers table)
    -- Removed: txt_records (use url_txt_records table)
    -- Removed: mx_records (use url_mx_records table)
    spf_record TEXT,
    dmarc_record TEXT,
    cipher_suite TEXT,
    key_algorithm TEXT,
    run_id TEXT,
    fingerprints_source TEXT, -- Kept for backward compatibility (deprecated, use runs table)
    fingerprints_version TEXT, -- Kept for backward compatibility (deprecated, use runs table)
    UNIQUE (final_domain, timestamp)
);

-- Step 2: Copy data (excluding JSON columns)
INSERT INTO url_status_new (
    id, domain, final_domain, ip_address, reverse_dns_name,
    status, status_description, response_time, title, keywords, description,
    linkedin_slug, security_headers, tls_version, ssl_cert_subject, ssl_cert_issuer,
    ssl_cert_valid_from, ssl_cert_valid_to, oids, is_mobile_friendly,
    timestamp, redirect_chain, spf_record, dmarc_record, cipher_suite,
    key_algorithm, run_id, fingerprints_source, fingerprints_version
)
SELECT
    id, domain, final_domain, ip_address, reverse_dns_name,
    status, status_description, response_time, title, keywords, description,
    linkedin_slug, security_headers, tls_version, ssl_cert_subject, ssl_cert_issuer,
    ssl_cert_valid_from, ssl_cert_valid_to, oids, is_mobile_friendly,
    timestamp, redirect_chain, spf_record, dmarc_record, cipher_suite,
    key_algorithm, run_id, fingerprints_source, fingerprints_version
FROM url_status;

-- Step 3: Drop old table and rename new one
DROP TABLE url_status;

-- Step 4: Rename new table to original name
ALTER TABLE url_status_new RENAME TO url_status;

-- Step 5: Recreate indexes
CREATE INDEX IF NOT EXISTS idx_url_status_domain ON url_status(domain);
CREATE INDEX IF NOT EXISTS idx_url_status_final_domain ON url_status(final_domain);
CREATE INDEX IF NOT EXISTS idx_url_status_timestamp ON url_status(timestamp);
CREATE INDEX IF NOT EXISTS idx_url_status_run_id_timestamp ON url_status(run_id, timestamp);

-- Note: The normalized child tables (url_technologies, url_nameservers, etc.)
-- already exist and contain the data. The foreign key constraints will remain valid
-- because we preserved the `id` column (PRIMARY KEY) in the new table.
