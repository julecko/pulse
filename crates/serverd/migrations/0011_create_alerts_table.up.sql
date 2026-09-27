-- Alerts the server generates when a rule fires: the history the mobile
-- app shows in its panel. Nothing generates them yet.
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- The rule that fired. Deleting a rule keeps its alerts as history, so
    -- everything needed to show one is stored on the alert itself.
    rule_id INTEGER REFERENCES alert_rules(id) ON DELETE SET NULL,
    -- The agent it's about; NULL = not about one agent (server-wide).
    agent_id INTEGER REFERENCES agents(id) ON DELETE CASCADE,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    title TEXT NOT NULL, -- "<rule name> on <hostname>", e.g. "CPU high on web01"
    message TEXT NOT NULL, -- e.g. "cpu_usage_percent 97.2 > 90 (for 5m)"
    triggered_at TEXT NOT NULL DEFAULT (datetime('now')), -- UTC
    resolved_at TEXT, -- UTC, when the condition cleared; NULL = still active
    acknowledged_at TEXT, -- UTC; NULL = nobody has acknowledged it
    acknowledged_by TEXT -- username
);

-- Panel: newest first, overall or per agent.
CREATE INDEX idx_alerts_triggered_at ON alerts (triggered_at);
CREATE INDEX idx_alerts_agent_id_triggered_at ON alerts (agent_id, triggered_at);
-- At most one active alert per rule and agent, so a condition that stays
-- true doesn't raise (and push) a new alert on every metrics snapshot.
CREATE UNIQUE INDEX idx_alerts_active_rule_agent ON alerts (rule_id, agent_id)
    WHERE resolved_at IS NULL;
