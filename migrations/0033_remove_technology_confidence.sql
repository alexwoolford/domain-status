-- Remove technology_confidence column from url_technologies table
-- Confidence scores are not useful (only 2 records had them)

-- Step 1: Create new table without the confidence column
CREATE TABLE IF NOT EXISTS url_technologies_new (
    id INTEGER PRIMARY KEY,
    url_status_id INTEGER NOT NULL,
    technology_name TEXT NOT NULL,
    technology_version TEXT,
    technology_category TEXT,
    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE
);

-- Step 2: Copy data from old table (excluding confidence column)
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

-- Step 4: Recreate indexes (without confidence index)
CREATE INDEX IF NOT EXISTS idx_url_technologies_name
    ON url_technologies(technology_name);

CREATE INDEX IF NOT EXISTS idx_url_technologies_status_id
    ON url_technologies(url_status_id);

CREATE INDEX IF NOT EXISTS idx_url_technologies_version
    ON url_technologies(technology_version);

CREATE INDEX IF NOT EXISTS idx_url_technologies_name_version
    ON url_technologies(technology_name, technology_version);

-- Step 5: Recreate unique indexes
CREATE UNIQUE INDEX IF NOT EXISTS idx_url_technologies_unique_with_version
    ON url_technologies(url_status_id, technology_name, technology_version)
    WHERE technology_version IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_url_technologies_unique_no_version
    ON url_technologies(url_status_id, technology_name)
    WHERE technology_version IS NULL;
