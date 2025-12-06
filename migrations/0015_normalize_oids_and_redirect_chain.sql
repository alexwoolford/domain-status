-- Normalize OIDs and redirect chain into separate tables
-- Both are JSON arrays that should be stored in normalized tables

-- Step 1: Create child table for OIDs
CREATE TABLE IF NOT EXISTS url_oids (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    oid TEXT NOT NULL,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE (url_status_id, oid)
);

CREATE INDEX IF NOT EXISTS idx_url_oids_oid
    ON url_oids(oid);

CREATE INDEX IF NOT EXISTS idx_url_oids_status_id
    ON url_oids(url_status_id);

-- Step 2: Create child table for redirect chain
-- Sequence order is important to preserve the order of redirects
CREATE TABLE IF NOT EXISTS url_redirect_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    sequence_order INTEGER NOT NULL,
    url TEXT NOT NULL,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE (url_status_id, sequence_order)
);

CREATE INDEX IF NOT EXISTS idx_url_redirect_chain_status_id
    ON url_redirect_chain(url_status_id);

-- Step 3: Migrate existing OIDs data from JSON column to normalized table
INSERT INTO url_oids (url_status_id, oid)
SELECT
    us.id,
    json_each.value
FROM url_status us,
     json_each(us.oids)
WHERE us.oids IS NOT NULL
  AND us.oids != '[]'
  AND us.oids != '';

-- Step 4: Migrate existing redirect chain data from JSON column to normalized table
-- Preserve sequence order using rowid from json_each
INSERT INTO url_redirect_chain (url_status_id, sequence_order, url)
SELECT
    us.id,
    json_each.key + 1 as sequence_order, -- json_each.key is 0-based, we want 1-based
    json_each.value
FROM url_status us,
     json_each(us.redirect_chain)
WHERE us.redirect_chain IS NOT NULL
  AND us.redirect_chain != '[]'
  AND us.redirect_chain != '';

-- Step 5: Remove oids and redirect_chain columns from url_status
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
    tls_version TEXT,
    ssl_cert_subject TEXT,
    ssl_cert_issuer TEXT,
    ssl_cert_valid_from INTEGER,
    ssl_cert_valid_to INTEGER,
    -- Removed: oids (use url_oids table)
    is_mobile_friendly BOOLEAN,
    timestamp INTEGER NOT NULL,
    -- Removed: redirect_chain (use url_redirect_chain table)
    spf_record TEXT,
    dmarc_record TEXT,
    cipher_suite TEXT,
    key_algorithm TEXT,
    run_id TEXT,
    UNIQUE (final_domain, timestamp)
);

-- Step 6: Copy data (excluding oids and redirect_chain columns)
INSERT INTO url_status_new (
    id, domain, final_domain, ip_address, reverse_dns_name,
    status, status_description, response_time, title, keywords, description,
    linkedin_slug, tls_version, ssl_cert_subject, ssl_cert_issuer,
    ssl_cert_valid_from, ssl_cert_valid_to, is_mobile_friendly,
    timestamp, spf_record, dmarc_record, cipher_suite,
    key_algorithm, run_id
)
SELECT
    id, domain, final_domain, ip_address, reverse_dns_name,
    status, status_description, response_time, title, keywords, description,
    linkedin_slug, tls_version, ssl_cert_subject, ssl_cert_issuer,
    ssl_cert_valid_from, ssl_cert_valid_to, is_mobile_friendly,
    timestamp, spf_record, dmarc_record, cipher_suite,
    key_algorithm, run_id
FROM url_status;

-- Step 7: Drop old table and rename new one
DROP TABLE url_status;

-- Step 8: Rename new table to original name
ALTER TABLE url_status_new RENAME TO url_status;

-- Step 9: Recreate indexes
CREATE INDEX IF NOT EXISTS idx_url_status_domain ON url_status(domain);
CREATE INDEX IF NOT EXISTS idx_url_status_final_domain ON url_status(final_domain);
CREATE INDEX IF NOT EXISTS idx_url_status_timestamp ON url_status(timestamp);
CREATE INDEX IF NOT EXISTS idx_url_status_run_id_timestamp ON url_status(run_id, timestamp);

-- Note: The normalized child tables (url_technologies, url_nameservers, url_txt_records,
-- url_mx_records, url_security_headers, url_oids, url_redirect_chain) already exist and contain
-- the data. The foreign key constraints will remain valid because we preserved the `id` column
-- (PRIMARY KEY) in the new table.
