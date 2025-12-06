-- Add geoip_version column to runs table
-- This stores the version/build date of the GeoIP database used for the run

ALTER TABLE runs ADD COLUMN geoip_version TEXT;

-- Note: geoip_version is NULL if GeoIP lookup was not enabled for the run
