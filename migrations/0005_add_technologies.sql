-- Add technologies column to store detected technologies as JSON array
ALTER TABLE url_status ADD COLUMN technologies TEXT;
