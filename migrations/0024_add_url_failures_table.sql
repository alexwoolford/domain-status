-- Migration: Add url_failures table and satellite tables
-- This tracks failed URL processing attempts separately from successful data
-- Following the star schema pattern: url_failures is the fact table, with satellite tables

-- Main failures fact table
CREATE TABLE IF NOT EXISTS url_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    final_url TEXT,  -- URL after redirects (if any redirects occurred before failure)
    domain TEXT NOT NULL,  -- Initial domain extracted from original URL
    final_domain TEXT,  -- Final domain after redirects (if any)
    error_type TEXT NOT NULL,  -- ErrorType enum value (e.g., "HttpRequestOtherError", "HttpRequestTimeoutError")
    error_message TEXT NOT NULL,  -- Full error message for debugging
    http_status INTEGER,  -- HTTP status code if available (e.g., 403, 500)
    retry_count INTEGER NOT NULL DEFAULT 0,  -- Number of retry attempts made
    elapsed_time_seconds NUMERIC(10, 2),  -- Time spent before failure
    timestamp INTEGER NOT NULL,  -- When the failure occurred (milliseconds since Unix epoch)
    run_id TEXT,  -- Foreign key to runs.run_id
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE SET NULL
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_url_failures_domain ON url_failures(domain);
CREATE INDEX IF NOT EXISTS idx_url_failures_final_domain ON url_failures(final_domain);
CREATE INDEX IF NOT EXISTS idx_url_failures_error_type ON url_failures(error_type);
CREATE INDEX IF NOT EXISTS idx_url_failures_http_status ON url_failures(http_status);
CREATE INDEX IF NOT EXISTS idx_url_failures_timestamp ON url_failures(timestamp);
CREATE INDEX IF NOT EXISTS idx_url_failures_run_id_timestamp ON url_failures(run_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_url_failures_url ON url_failures(url);  -- For finding all failures for a specific URL

-- Satellite table: redirect chain before failure
-- Tracks redirects that occurred before the failure (useful for debugging bot detection)
CREATE TABLE IF NOT EXISTS url_failure_redirect_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_failure_id INTEGER NOT NULL,
    redirect_url TEXT NOT NULL,
    redirect_order INTEGER NOT NULL,  -- Order in the redirect chain (0 = first redirect)
    FOREIGN KEY (url_failure_id) REFERENCES url_failures(id) ON DELETE CASCADE,
    UNIQUE(url_failure_id, redirect_order)
);

CREATE INDEX IF NOT EXISTS idx_url_failure_redirect_chain_failure_id ON url_failure_redirect_chain(url_failure_id);

-- Satellite table: response headers received before failure
-- Useful for analyzing bot detection patterns (e.g., Cloudflare headers, rate limit headers)
CREATE TABLE IF NOT EXISTS url_failure_response_headers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_failure_id INTEGER NOT NULL,
    header_name TEXT NOT NULL,
    header_value TEXT NOT NULL,
    FOREIGN KEY (url_failure_id) REFERENCES url_failures(id) ON DELETE CASCADE,
    UNIQUE(url_failure_id, header_name)
);

CREATE INDEX IF NOT EXISTS idx_url_failure_response_headers_failure_id ON url_failure_response_headers(url_failure_id);

-- Satellite table: request headers sent (for debugging bot detection)
-- Helps understand what headers we sent that might have triggered blocking
CREATE TABLE IF NOT EXISTS url_failure_request_headers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_failure_id INTEGER NOT NULL,
    header_name TEXT NOT NULL,
    header_value TEXT NOT NULL,
    FOREIGN KEY (url_failure_id) REFERENCES url_failures(id) ON DELETE CASCADE,
    UNIQUE(url_failure_id, header_name)
);

CREATE INDEX IF NOT EXISTS idx_url_failure_request_headers_failure_id ON url_failure_request_headers(url_failure_id);


