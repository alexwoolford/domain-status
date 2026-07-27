-- High-value capture: landing URLs, meta robots, and script-host inventory.
-- All signals are already in memory during a scan (no extra network I/O).

ALTER TABLE url_status ADD COLUMN initial_url TEXT;
ALTER TABLE url_status ADD COLUMN final_url TEXT;
ALTER TABLE url_status ADD COLUMN meta_robots TEXT;

CREATE TABLE IF NOT EXISTS url_script_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_status_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    registrable_domain TEXT,
    is_first_party INTEGER NOT NULL DEFAULT 0,

    FOREIGN KEY (url_status_id) REFERENCES url_status(id) ON DELETE CASCADE,
    UNIQUE(url_status_id, host)
);

CREATE INDEX IF NOT EXISTS idx_url_script_hosts_host ON url_script_hosts(host);
CREATE INDEX IF NOT EXISTS idx_url_script_hosts_first_party
    ON url_script_hosts(is_first_party);
