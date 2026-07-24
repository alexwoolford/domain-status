-- Scan-completeness signals for secret-detection FN awareness.
-- body_truncated: response body hit MAX_RESPONSE_BODY_SIZE (prefix still scanned).
-- external_scripts_*: first-party <script src> candidates vs actually fetched
--   when --scan-external-scripts is on; both remain 0 when the flag is off.

ALTER TABLE url_status ADD COLUMN body_truncated INTEGER NOT NULL DEFAULT 0;
ALTER TABLE url_status ADD COLUMN external_scripts_eligible INTEGER NOT NULL DEFAULT 0;
ALTER TABLE url_status ADD COLUMN external_scripts_scanned INTEGER NOT NULL DEFAULT 0;
