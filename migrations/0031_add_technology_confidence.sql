-- Add technology_confidence column to url_technologies table
-- This stores the confidence score (0-100) for each detected technology, matching wappalyzergo behavior

-- Step 1: Add technology_confidence column (nullable, as confidence may not always be available)
ALTER TABLE url_technologies ADD COLUMN technology_confidence INTEGER;

-- Step 2: Create index on confidence for filtering/querying by confidence level
CREATE INDEX IF NOT EXISTS idx_url_technologies_confidence
    ON url_technologies(technology_confidence);
