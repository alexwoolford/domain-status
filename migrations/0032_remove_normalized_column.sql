-- Remove technology_version_normalized generated column
-- Replace unique constraint with a unique index that handles NULL versions

-- Step 1: Create new table without the generated column
CREATE TABLE IF NOT EXISTS url_technologies_new (
    id INTEGER PRIMARY KEY,
    url_status_id INTEGER NOT NULL,
    technology_name TEXT NOT NULL,
    technology_version TEXT, -- NULL means no version detected
    technology_category TEXT,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE
);

-- Step 2: Copy data from old table
INSERT INTO url_technologies_new (id, url_status_id, technology_name, technology_version, technology_category)
SELECT
    id,
    url_status_id,
    technology_name,
    technology_version,
    technology_category
FROM url_technologies;

-- Step 3: Drop old table and rename new one
DROP TABLE url_technologies;
ALTER TABLE url_technologies_new RENAME TO url_technologies;

-- Step 4: Recreate indexes
CREATE INDEX IF NOT EXISTS idx_url_technologies_name
    ON url_technologies(technology_name);

CREATE INDEX IF NOT EXISTS idx_url_technologies_status_id
    ON url_technologies(url_status_id);

CREATE INDEX IF NOT EXISTS idx_url_technologies_version
    ON url_technologies(technology_version);

CREATE INDEX IF NOT EXISTS idx_url_technologies_name_version
    ON url_technologies(technology_name, technology_version);

-- Step 5: Create unique indexes that handle NULL versions
-- SQLite unique indexes treat NULL values as distinct, so we need two indexes:
-- 1. A unique index for non-NULL versions: (url_status_id, technology_name, technology_version)
-- 2. A partial unique index for NULL versions: (url_status_id, technology_name) WHERE technology_version IS NULL
-- This ensures:
-- - Same tech with different versions can coexist
-- - Only one NULL version per tech per URL

-- Unique index for non-NULL versions
CREATE UNIQUE INDEX IF NOT EXISTS idx_url_technologies_unique_with_version
    ON url_technologies(url_status_id, technology_name, technology_version)
    WHERE technology_version IS NOT NULL;

-- Partial unique index for NULL versions (only one NULL per tech per URL)
CREATE UNIQUE INDEX IF NOT EXISTS idx_url_technologies_unique_no_version
    ON url_technologies(url_status_id, technology_name)
    WHERE technology_version IS NULL;
