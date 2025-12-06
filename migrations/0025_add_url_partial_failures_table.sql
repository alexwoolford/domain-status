-- Migration: Add url_partial_failures table for DNS/TLS errors that don't prevent URL processing
-- These are "partial failures" - the URL was successfully processed, but some supplementary
-- data (DNS or TLS) failed to be retrieved.

CREATE TABLE IF NOT EXISTS url_partial_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    error_type TEXT NOT NULL,  -- DNS NS lookup error, DNS TXT lookup error, DNS MX lookup error, TLS certificate error
    error_message TEXT NOT NULL,
    timestamp INTEGER NOT NULL,  -- Milliseconds since Unix epoch
    run_id TEXT,  -- Foreign key to runs.run_id
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE SET NULL
);

-- Index for querying partial failures by run
CREATE INDEX IF NOT EXISTS idx_url_partial_failures_run_id ON url_partial_failures(run_id);

-- Index for querying partial failures by error type
CREATE INDEX IF NOT EXISTS idx_url_partial_failures_error_type ON url_partial_failures(error_type);

-- Index for querying partial failures by url_status_id
CREATE INDEX IF NOT EXISTS idx_url_partial_failures_url_status_id ON url_partial_failures(url_status_id);
