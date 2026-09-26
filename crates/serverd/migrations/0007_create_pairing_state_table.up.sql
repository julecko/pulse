-- Whether `POST /agents/pair` accepts new agents, toggled by users via
-- `GET/PUT /agents/pairing` (`pulse-server-cli agents pairing ...`). A
-- single row. Closed by default, including for existing installs: new
-- agents can only register while a user has opened pairing.
CREATE TABLE pairing_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    open INTEGER NOT NULL DEFAULT 0, -- 0 | 1
    open_until TEXT, -- UTC; NULL = until closed. Ignored while closed.
    updated_by TEXT, -- username of the last user to change it
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO pairing_state (id) VALUES (1);
