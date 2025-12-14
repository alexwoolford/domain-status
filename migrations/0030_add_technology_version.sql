-- Add technology_version column to url_technologies table
-- This separates version information from technology_name for better queryability and normalization
--
-- Migration strategy:
-- 1. Add the new column (nullable initially)
-- 2. Parse existing "Technology:version" format and split into name and version
-- 3. Update unique constraint to include version (same tech with different versions = different rows)
-- 4. Make version column NOT NULL (after migration)

-- Step 1: Add technology_version column (nullable initially)
ALTER TABLE url_technologies ADD COLUMN technology_version TEXT;

-- Step 2: Migrate existing data
-- Parse "Technology:version" format and split into name and version
-- For entries with ":", split on first colon
-- For entries without ":", keep name as-is and set version to NULL
UPDATE url_technologies
SET
    technology_name = CASE
        WHEN INSTR(technology_name, ':') > 0
        THEN SUBSTR(technology_name, 1, INSTR(technology_name, ':') - 1)
        ELSE technology_name
    END,
    technology_version = CASE
        WHEN INSTR(technology_name, ':') > 0
        THEN SUBSTR(technology_name, INSTR(technology_name, ':') + 1)
        ELSE NULL
    END
WHERE technology_name LIKE '%:%';

-- Step 3: We need to recreate the table to update the unique constraint
-- SQLite doesn't support DROP CONSTRAINT, so we'll recreate the table
-- This allows the same technology with different versions to coexist

-- Create new table with version column and updated unique constraint
-- Use a generated column to normalize NULL versions to empty string for unique constraint
CREATE TABLE IF NOT EXISTS url_technologies_new (
    id INTEGER PRIMARY KEY,
    url_status_id INTEGER NOT NULL,
    technology_name TEXT NOT NULL,
    technology_version TEXT, -- NULL means no version detected
    technology_version_normalized TEXT GENERATED ALWAYS AS (COALESCE(technology_version, '')) STORED,
    technology_category TEXT,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    -- Allow same technology with different versions (or no version) per URL
    UNIQUE(url_status_id, technology_name, technology_version_normalized)
);

-- Copy data from old table to new table (parsing Technology:version format)
-- The generated column will automatically normalize NULL versions to empty string
INSERT INTO url_technologies_new (id, url_status_id, technology_name, technology_version, technology_category)
SELECT
    id,
    url_status_id,
    CASE
        WHEN INSTR(technology_name, ':') > 0
        THEN SUBSTR(technology_name, 1, INSTR(technology_name, ':') - 1)
        ELSE technology_name
    END as technology_name,
    CASE
        WHEN INSTR(technology_name, ':') > 0
        THEN SUBSTR(technology_name, INSTR(technology_name, ':') + 1)
        ELSE NULL
    END as technology_version,
    technology_category
FROM url_technologies;

-- Drop old table and rename new one
DROP TABLE url_technologies;
ALTER TABLE url_technologies_new RENAME TO url_technologies;

-- Step 4: Recreate indexes
CREATE INDEX IF NOT EXISTS idx_url_technologies_name
    ON url_technologies(technology_name);

CREATE INDEX IF NOT EXISTS idx_url_technologies_status_id
    ON url_technologies(url_status_id);

-- Step 5: Create index on technology_version for version-based queries
CREATE INDEX IF NOT EXISTS idx_url_technologies_version
    ON url_technologies(technology_version);

-- Step 6: Create composite index for name+version queries
CREATE INDEX IF NOT EXISTS idx_url_technologies_name_version
    ON url_technologies(technology_name, technology_version);
