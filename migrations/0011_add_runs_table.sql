-- Create runs table to store run-level metadata
-- This stores information that applies to the entire run, not individual URLs
-- Examples: fingerprints_source, fingerprints_version, start_time, end_time

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    fingerprints_source TEXT,
    fingerprints_version TEXT,
    start_time INTEGER NOT NULL, -- milliseconds since Unix epoch
    end_time INTEGER, -- milliseconds since Unix epoch (NULL if run still in progress)
    total_urls INTEGER DEFAULT 0,
    successful_urls INTEGER DEFAULT 0,
    failed_urls INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_runs_start_time 
    ON runs(start_time);

-- Note: We keep fingerprints_source and fingerprints_version in url_status for backward compatibility
-- but they should be queried from the runs table instead

