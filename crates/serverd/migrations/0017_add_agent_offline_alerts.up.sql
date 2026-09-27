-- Offline alerts: an alert when an approved agent sends no metrics for
-- longer than its `offline_after_secs` (set per agent with
-- `PUT /agents/{id}/offline-alert`, `pulse-server-cli agents offline-alert
-- set`). NULL = off, the default.
ALTER TABLE agents ADD COLUMN last_metrics_at TEXT; -- UTC, last snapshot received
ALTER TABLE agents ADD COLUMN offline_after_secs INTEGER
    CHECK (offline_after_secs IS NULL OR offline_after_secs BETWEEN 60 AND 2592000);
-- When offline_after_secs was last set: counts as "last seen" for an agent
-- that hasn't sent metrics since, so it isn't declared offline at once.
ALTER TABLE agents ADD COLUMN offline_after_set_at TEXT;

UPDATE agents SET last_metrics_at = (SELECT MAX(created_at) FROM metrics WHERE agent_id = agents.id);

-- Marks which alerts are offline alerts (the alert itself is a normal
-- `alerts` row, no rule). Resolved when the agent sends metrics again.
CREATE TABLE offline_alerts (
    alert_id INTEGER PRIMARY KEY REFERENCES alerts(id) ON DELETE CASCADE
);
