-- ============================================================================
-- Migration: Change run_id FK from ON DELETE SET NULL to ON DELETE CASCADE
-- ============================================================================
-- SQLite cannot ALTER TABLE to change a foreign key. We recreate each table
-- with the new FK action, copy data, drop the old table, and rename.
-- Run with PRAGMA foreign_keys = OFF so we can drop tables that are still
-- referenced (e.g. url_status by url_partial_failures).
-- ============================================================================

PRAGMA foreign_keys = OFF;

-- ----------------------------------------------------------------------------
-- url_status: recreate with run_id ON DELETE CASCADE
-- ----------------------------------------------------------------------------
CREATE TABLE url_status_new (
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
    UNIQUE(final_domain, observed_at_ms),
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);
INSERT INTO url_status_new SELECT * FROM url_status;
DROP TABLE url_status;
ALTER TABLE url_status_new RENAME TO url_status;
CREATE INDEX idx_url_status_initial_domain ON url_status(initial_domain);
CREATE INDEX idx_url_status_final_domain ON url_status(final_domain);
CREATE INDEX idx_url_status_http_status ON url_status(http_status);
CREATE INDEX idx_url_status_observed_at ON url_status(observed_at_ms);
CREATE INDEX idx_url_status_run_id ON url_status(run_id, observed_at_ms);

-- ----------------------------------------------------------------------------
-- url_failures: recreate with run_id ON DELETE CASCADE
-- ----------------------------------------------------------------------------
CREATE TABLE url_failures_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attempted_url TEXT NOT NULL,
    final_url TEXT,
    initial_domain TEXT NOT NULL,
    final_domain TEXT,
    error_type TEXT NOT NULL,
    error_message TEXT NOT NULL,
    http_status INTEGER,
    retry_count INTEGER NOT NULL DEFAULT 0,
    elapsed_time_seconds REAL,
    observed_at_ms INTEGER NOT NULL,
    run_id TEXT,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);
INSERT INTO url_failures_new SELECT * FROM url_failures;
DROP TABLE url_failures;
ALTER TABLE url_failures_new RENAME TO url_failures;
CREATE INDEX idx_url_failures_initial_domain ON url_failures(initial_domain);
CREATE INDEX idx_url_failures_error_type ON url_failures(error_type);
CREATE INDEX idx_url_failures_http_status ON url_failures(http_status);
CREATE INDEX idx_url_failures_run_id ON url_failures(run_id, observed_at_ms);

-- ----------------------------------------------------------------------------
-- url_partial_failures: recreate with run_id ON DELETE CASCADE
-- ----------------------------------------------------------------------------
CREATE TABLE url_partial_failures_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    error_type TEXT NOT NULL,
    error_message TEXT NOT NULL,
    observed_at_ms INTEGER NOT NULL,
    run_id TEXT,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);
INSERT INTO url_partial_failures_new SELECT * FROM url_partial_failures;
DROP TABLE url_partial_failures;
ALTER TABLE url_partial_failures_new RENAME TO url_partial_failures;
CREATE INDEX idx_url_partial_failures_error_type ON url_partial_failures(error_type);
CREATE INDEX idx_url_partial_failures_run_id ON url_partial_failures(run_id);

PRAGMA foreign_keys = ON;
