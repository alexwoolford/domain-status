-- Add run_id column for time-series tracking
-- This allows comparing data across different runs to track changes over time
ALTER TABLE url_status ADD COLUMN run_id TEXT;

-- Create index for efficient run-based queries
-- This enables fast queries like "show me all domains from run X" or
-- "compare technologies between run X and run Y"
CREATE INDEX IF NOT EXISTS idx_url_status_run_id_timestamp
    ON url_status(run_id, timestamp);
