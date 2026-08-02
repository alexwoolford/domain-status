-- ============================================================================
-- Migration: Drop unpopulated url_status / favicon columns
-- ============================================================================
-- keywords, is_mobile_friendly, body_word_count, body_line_count, and
-- url_favicons.base64_data are no longer captured. Rebuild tables without them
-- (SQLite cannot drop multiple columns portably across all supported builds).
-- ============================================================================

PRAGMA foreign_keys=OFF;

CREATE TABLE url_status__mig0014 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    initial_domain TEXT NOT NULL,
    final_domain TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    reverse_dns_name TEXT,
    http_status INTEGER NOT NULL,
    http_status_text TEXT NOT NULL,
    response_time_seconds REAL NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    tls_version TEXT,
    cipher_suite TEXT,
    key_algorithm TEXT,
    ssl_cert_subject TEXT,
    ssl_cert_issuer TEXT,
    ssl_cert_valid_from_ms INTEGER,
    ssl_cert_valid_to_ms INTEGER,
    spf_record TEXT,
    dmarc_record TEXT,
    observed_at_ms INTEGER NOT NULL,
    run_id TEXT,
    body_sha256 TEXT,
    content_length INTEGER,
    http_version TEXT,
    content_type TEXT,
    canonical_url TEXT,
    cert_fingerprint_sha256 TEXT,
    cert_serial_number TEXT,
    cert_is_self_signed BOOLEAN,
    cert_is_wildcard BOOLEAN,
    cert_is_mismatched BOOLEAN,
    meta_refresh_url TEXT,
    body_truncated INTEGER NOT NULL DEFAULT 0,
    external_scripts_eligible INTEGER NOT NULL DEFAULT 0,
    external_scripts_scanned INTEGER NOT NULL DEFAULT 0,
    initial_url TEXT,
    final_url TEXT,
    meta_robots TEXT,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

INSERT INTO url_status__mig0014 (
    id, initial_domain, final_domain, ip_address, reverse_dns_name,
    http_status, http_status_text, response_time_seconds, title, description,
    tls_version, cipher_suite, key_algorithm, ssl_cert_subject, ssl_cert_issuer,
    ssl_cert_valid_from_ms, ssl_cert_valid_to_ms, spf_record, dmarc_record,
    observed_at_ms, run_id, body_sha256, content_length, http_version,
    content_type, canonical_url, cert_fingerprint_sha256, cert_serial_number,
    cert_is_self_signed, cert_is_wildcard, cert_is_mismatched, meta_refresh_url,
    body_truncated, external_scripts_eligible, external_scripts_scanned,
    initial_url, final_url, meta_robots
)
SELECT
    id, initial_domain, final_domain, ip_address, reverse_dns_name,
    http_status, http_status_text, response_time_seconds, title, description,
    tls_version, cipher_suite, key_algorithm, ssl_cert_subject, ssl_cert_issuer,
    ssl_cert_valid_from_ms, ssl_cert_valid_to_ms, spf_record, dmarc_record,
    observed_at_ms, run_id, body_sha256, content_length, http_version,
    content_type, canonical_url, cert_fingerprint_sha256, cert_serial_number,
    cert_is_self_signed, cert_is_wildcard, cert_is_mismatched, meta_refresh_url,
    body_truncated, external_scripts_eligible, external_scripts_scanned,
    initial_url, final_url, meta_robots
FROM url_status;

DROP TABLE url_status;
ALTER TABLE url_status__mig0014 RENAME TO url_status;

CREATE INDEX IF NOT EXISTS idx_url_status_initial_domain ON url_status(initial_domain);
CREATE INDEX IF NOT EXISTS idx_url_status_final_domain ON url_status(final_domain);
CREATE INDEX IF NOT EXISTS idx_url_status_http_status ON url_status(http_status);
CREATE INDEX IF NOT EXISTS idx_url_status_observed_at ON url_status(observed_at_ms);
CREATE INDEX IF NOT EXISTS idx_url_status_run_id ON url_status(run_id, observed_at_ms);

CREATE UNIQUE INDEX IF NOT EXISTS idx_url_status_run_initial_domain
ON url_status(run_id, initial_domain);

CREATE TABLE url_favicons__mig0014 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    favicon_url TEXT NOT NULL,
    hash INTEGER NOT NULL,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id)
);

INSERT INTO url_favicons__mig0014 (id, url_status_id, favicon_url, hash)
SELECT id, url_status_id, favicon_url, hash
FROM url_favicons;

DROP TABLE url_favicons;
ALTER TABLE url_favicons__mig0014 RENAME TO url_favicons;

CREATE INDEX IF NOT EXISTS idx_url_favicons_hash ON url_favicons(hash);

PRAGMA foreign_keys=ON;
