-- Add skipped_urls to runs for data integrity (total = successful + failed + skipped).
ALTER TABLE runs ADD COLUMN skipped_urls INTEGER NOT NULL DEFAULT 0;
