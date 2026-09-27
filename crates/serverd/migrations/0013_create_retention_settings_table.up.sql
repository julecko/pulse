-- Retention periods users set at runtime (`PUT /retention/{data}`,
-- `pulse-server-cli retention set`), overriding the server config's
-- `[retention]` defaults. No row for a kind of data = its config default.
CREATE TABLE retention_settings (
    data TEXT PRIMARY KEY CHECK (data IN ('metrics', 'auth_events', 'alerts')),
    days INTEGER NOT NULL CHECK (days BETWEEN 0 AND 3650), -- 0 = keep forever
    updated_by TEXT, -- username
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
