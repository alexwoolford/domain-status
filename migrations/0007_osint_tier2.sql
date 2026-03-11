-- ============================================================================
-- Tier 2 OSINT additions: CNAME chain, AAAA (IPv6), CAA records
-- ============================================================================

-- CNAME chain stored as JSON array on fact table (single chain per domain)
ALTER TABLE url_status ADD COLUMN cname_chain TEXT;

-- AAAA (IPv6) addresses - satellite table
CREATE TABLE IF NOT EXISTS url_ipv6_addresses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    ipv6_address TEXT NOT NULL,

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, ipv6_address)
);

CREATE INDEX idx_url_ipv6_addresses_address ON url_ipv6_addresses(ipv6_address);

-- CAA (Certificate Authority Authorization) records - satellite table
CREATE TABLE IF NOT EXISTS url_caa_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    flag INTEGER NOT NULL,           -- 0 = non-critical, 128 = critical
    tag TEXT NOT NULL,               -- 'issue', 'issuewild', 'iodef'
    value TEXT NOT NULL,             -- CA domain or reporting URI

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, tag, value)
);

CREATE INDEX idx_url_caa_records_tag ON url_caa_records(tag);
