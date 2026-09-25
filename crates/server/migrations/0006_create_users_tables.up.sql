-- Users are only ever created via `server user add` (direct DB access);
-- there's deliberately no registration endpoint.
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL, -- argon2id, PHC string format
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE user_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE, -- SHA-256 of the bearer token, hex
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
);

CREATE INDEX idx_user_sessions_expires_at ON user_sessions (expires_at);
