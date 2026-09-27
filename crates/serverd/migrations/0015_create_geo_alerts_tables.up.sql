-- Geo alerts: an alert when an SSH login comes from an IP outside the
-- allowed countries (looked up in a MaxMind GeoLite2 City database).
-- Settings are one row, changed with `PUT /geo-alerts/settings`
-- (`pulse-server-cli geo-alerts set`). Off (no allowed countries) by default.
CREATE TABLE geo_alert_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    allowed_countries TEXT NOT NULL DEFAULT '', -- ISO codes, comma-separated; '' = off
    include_failures INTEGER NOT NULL DEFAULT 0, -- 0 | 1: failed logins too
    notify INTEGER NOT NULL DEFAULT 1, -- 0 | 1: push them
    updated_by TEXT, -- username
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO geo_alert_settings (id) VALUES (1);

-- What each geo alert is about. The alert itself is a normal `alerts` row
-- (rule_id NULL), so listing, acknowledging, pushing and retention work as
-- for rule alerts; this adds the details, joined on alert_id.
CREATE TABLE geo_alerts (
    alert_id INTEGER PRIMARY KEY REFERENCES alerts(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('session_open', 'auth_failure')),
    ip TEXT NOT NULL,
    user TEXT NOT NULL, -- PAM user; for failures, whatever the client sent
    country_code TEXT, -- ISO 3166-1 alpha-2; NULL = IP not in the database
    country_name TEXT,
    city TEXT
);

-- At most one active geo alert per agent, IP and kind (see alerting.rs).
CREATE INDEX idx_geo_alerts_ip_kind ON geo_alerts (ip, kind);
