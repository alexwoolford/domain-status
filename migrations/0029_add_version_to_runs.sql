-- Add version column to runs table
-- This stores the application version that ran the scan for data provenance
-- Useful for debugging issues tied to specific versions

ALTER TABLE runs ADD COLUMN version TEXT;

-- Set version for existing runs (if any) to NULL - they were run before version tracking
-- In practice, this will only affect test databases
