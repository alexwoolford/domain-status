-- Add fingerprints metadata columns to track source and version
ALTER TABLE url_status ADD COLUMN fingerprints_source TEXT;
ALTER TABLE url_status ADD COLUMN fingerprints_version TEXT;

