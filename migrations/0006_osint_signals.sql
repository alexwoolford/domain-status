-- ============================================================================
-- OSINT signal additions (Tier 1 + Tier 2)
--
-- Tier 1: Content metrics and fingerprints from existing HTTP/TLS data
-- Tier 2: DNS record types (CNAME, AAAA, CAA)
--
-- Design: scalar values on url_status, multi-valued data in satellite tables.
-- ============================================================================

-- Response body SHA-256 hash for fingerprinting identical pages across domains
ALTER TABLE url_status ADD COLUMN body_sha256 TEXT;

-- Response body length in bytes
ALTER TABLE url_status ADD COLUMN content_length INTEGER;

-- HTTP protocol version (HTTP/1.0, HTTP/1.1, HTTP/2)
ALTER TABLE url_status ADD COLUMN http_version TEXT;

-- Word and line count for content analysis and fingerprinting
ALTER TABLE url_status ADD COLUMN body_word_count INTEGER;
ALTER TABLE url_status ADD COLUMN body_line_count INTEGER;

-- Content-Type header as standalone queryable field
ALTER TABLE url_status ADD COLUMN content_type TEXT;

-- Canonical URL from <link rel="canonical">
ALTER TABLE url_status ADD COLUMN canonical_url TEXT;

-- SHA-256 fingerprint of the leaf TLS certificate DER
ALTER TABLE url_status ADD COLUMN cert_fingerprint_sha256 TEXT;

-- HTTP status code per redirect hop (301 vs 302 matters for SEO/caching)
ALTER TABLE url_redirect_chain ADD COLUMN http_status INTEGER;

-- ============================================================================
-- Satellite tables for multi-valued DNS records
-- ============================================================================

-- CNAME records - reveals CDN/hosting infrastructure
CREATE TABLE IF NOT EXISTS url_cname_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    cname_target TEXT NOT NULL,

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, cname_target)
);

CREATE INDEX idx_url_cname_records_target ON url_cname_records(cname_target);

-- AAAA (IPv6) addresses - dual-stack detection
CREATE TABLE IF NOT EXISTS url_ipv6_addresses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    ipv6_address TEXT NOT NULL,

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, ipv6_address)
);

CREATE INDEX idx_url_ipv6_addresses_address ON url_ipv6_addresses(ipv6_address);

-- CAA (Certificate Authority Authorization) records - security posture
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
