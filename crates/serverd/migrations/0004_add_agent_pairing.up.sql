-- SQLite's ALTER TABLE ADD COLUMN can't add a UNIQUE constraint directly,
-- so the column is added plain and uniqueness is enforced via an index.
ALTER TABLE agents ADD COLUMN fingerprint TEXT NOT NULL DEFAULT '';
ALTER TABLE agents ADD COLUMN status TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE agents ADD COLUMN token TEXT;

CREATE UNIQUE INDEX idx_agents_fingerprint ON agents (fingerprint);
