-- Alert rules: conditions users set up, checked per agent. Nothing
-- evaluates them yet.
CREATE TABLE alert_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    -- The agent this rule watches; NULL = every agent.
    agent_id INTEGER REFERENCES agents(id) ON DELETE CASCADE,
    -- One of protocol::AlertMetric (cpu_usage_percent, memory_used_percent,
    -- ...); checked by the server, not here, so adding one needs no migration.
    metric TEXT NOT NULL,
    operator TEXT NOT NULL CHECK (operator IN ('>', '>=', '<', '<=')),
    threshold REAL NOT NULL,
    -- How long the condition must hold before the rule fires; 0 = at once.
    duration_secs INTEGER NOT NULL DEFAULT 0 CHECK (duration_secs >= 0),
    -- Copied onto each alert the rule generates.
    severity TEXT NOT NULL DEFAULT 'warning' CHECK (severity IN ('info', 'warning', 'critical')),
    -- Push each alert this rule fires to every registered device (all users).
    notify INTEGER NOT NULL DEFAULT 0, -- 0 | 1
    enabled INTEGER NOT NULL DEFAULT 1, -- 0 | 1
    created_by TEXT, -- username of the user who created it
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_alert_rules_agent_id ON alert_rules (agent_id);
