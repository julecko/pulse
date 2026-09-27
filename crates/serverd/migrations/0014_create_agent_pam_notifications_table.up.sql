-- Which of an agent's PAM events are pushed to every registered device
-- (`PUT /agents/{id}/pam-notifications`, `pulse-server-cli agents
-- pam-notify set`). One row per pushed kind; no rows = nothing pushed, the
-- default. Events are stored either way.
CREATE TABLE agent_pam_notifications (
    agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('session_open', 'session_close', 'auth_failure')),
    PRIMARY KEY (agent_id, kind)
);
