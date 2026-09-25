CREATE TABLE auth_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    kind TEXT NOT NULL, -- session_open | session_close | auth_failure
    service TEXT NOT NULL,
    user TEXT NOT NULL,
    ruser TEXT,
    rhost TEXT,
    tty TEXT,
    occurred_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_auth_events_agent_id_occurred_at ON auth_events (agent_id, occurred_at);
