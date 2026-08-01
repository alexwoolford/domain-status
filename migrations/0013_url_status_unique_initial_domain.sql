-- ============================================================================
-- Migration: One url_status row per run_id + initial_domain (not final_domain)
-- ============================================================================
-- UNIQUE(run_id, final_domain) collapsed distinct input hosts that redirected to
-- the same final host (e.g. multiple parked domains → parked.example.com). That made
-- successful_urls exceed url_status rows and erased earlier initial_domain values.
-- Idempotency for duplicate lines in the same input file is preserved via
-- UNIQUE(run_id, initial_domain) (extract_domain normalizes www.).
--
-- Also drop table UNIQUE(final_domain, observed_at_ms): concurrent scans that share
-- a final host can share the same observed_at_ms millisecond and would still collide
-- after switching the run-level key. SQLite requires a table rebuild to remove it.
-- ============================================================================

PRAGMA foreign_keys=OFF;

DROP INDEX IF EXISTS idx_url_status_run_final_domain;

CREATE TABLE url_status__mig0013 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    initial_domain TEXT NOT NULL,
    final_domain TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    reverse_dns_name TEXT,
    http_status INTEGER NOT NULL,
    http_status_text TEXT NOT NULL,
    response_time_seconds REAL NOT NULL,
    title TEXT NOT NULL,
    keywords TEXT,
    description TEXT,
    is_mobile_friendly BOOLEAN NOT NULL DEFAULT 0,
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
    body_word_count INTEGER,
    body_line_count INTEGER,
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

INSERT INTO url_status__mig0013 (
    id, initial_domain, final_domain, ip_address, reverse_dns_name,
    http_status, http_status_text, response_time_seconds, title, keywords,
    description, is_mobile_friendly, tls_version, cipher_suite, key_algorithm,
    ssl_cert_subject, ssl_cert_issuer, ssl_cert_valid_from_ms, ssl_cert_valid_to_ms,
    spf_record, dmarc_record, observed_at_ms, run_id, body_sha256, content_length,
    http_version, body_word_count, body_line_count, content_type, canonical_url,
    cert_fingerprint_sha256, cert_serial_number, cert_is_self_signed, cert_is_wildcard,
    cert_is_mismatched, meta_refresh_url, body_truncated, external_scripts_eligible,
    external_scripts_scanned, initial_url, final_url, meta_robots
)
SELECT
    id, initial_domain, final_domain, ip_address, reverse_dns_name,
    http_status, http_status_text, response_time_seconds, title, keywords,
    description, is_mobile_friendly, tls_version, cipher_suite, key_algorithm,
    ssl_cert_subject, ssl_cert_issuer, ssl_cert_valid_from_ms, ssl_cert_valid_to_ms,
    spf_record, dmarc_record, observed_at_ms, run_id, body_sha256, content_length,
    http_version, body_word_count, body_line_count, content_type, canonical_url,
    cert_fingerprint_sha256, cert_serial_number, cert_is_self_signed, cert_is_wildcard,
    cert_is_mismatched, meta_refresh_url, body_truncated, external_scripts_eligible,
    external_scripts_scanned, initial_url, final_url, meta_robots
FROM url_status;

DROP TABLE url_status;
ALTER TABLE url_status__mig0013 RENAME TO url_status;

CREATE INDEX IF NOT EXISTS idx_url_status_initial_domain ON url_status(initial_domain);
CREATE INDEX IF NOT EXISTS idx_url_status_final_domain ON url_status(final_domain);
CREATE INDEX IF NOT EXISTS idx_url_status_http_status ON url_status(http_status);
CREATE INDEX IF NOT EXISTS idx_url_status_observed_at ON url_status(observed_at_ms);
CREATE INDEX IF NOT EXISTS idx_url_status_run_id ON url_status(run_id, observed_at_ms);

CREATE UNIQUE INDEX IF NOT EXISTS idx_url_status_run_initial_domain
ON url_status(run_id, initial_domain);

PRAGMA foreign_keys=ON;
