-- Add elapsed_seconds column to runs table
-- This stores the total execution time in seconds for easier querying
-- Can be calculated from (end_time - start_time) / 1000.0, but storing it
-- makes queries simpler and avoids floating point precision issues

ALTER TABLE runs ADD COLUMN elapsed_seconds REAL;

-- Calculate elapsed_seconds for existing runs that have end_time
UPDATE runs
SET elapsed_seconds = (end_time - start_time) / 1000.0
WHERE end_time IS NOT NULL;
