-- Add observed-vs-implied flag for technology fingerprint rows.
-- Implied techs come from another technology's `implies` list (e.g. WordPress → MySQL),
-- not from a direct pattern match on the response.
ALTER TABLE url_technologies ADD COLUMN is_implied INTEGER NOT NULL DEFAULT 0;
