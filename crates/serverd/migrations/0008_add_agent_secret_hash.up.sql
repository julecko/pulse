-- Agents now authenticate with a secret they generate themselves, sent with
-- every pairing poll and used as their bearer token once approved; the
-- server stores only its SHA-256 and never hands a credential out (before,
-- `/agents/pair` returned the plaintext `token` to anyone who knew an
-- approved agent's fingerprint).
--
-- Existing approved agents keep working: their old token becomes their
-- secret. SQLite has no SHA-256, so the server hashes `token` into
-- `secret_hash` on startup and clears it (`db::hash_legacy_agent_tokens`).
--
-- Pending requests are dropped: they have no secret to prove ownership, and
-- letting the first poll that brings one claim the row would let anyone who
-- saw the fingerprint claim it. Those agents register again (with a secret)
-- next time pairing is open. They have no metrics or events to cascade.
ALTER TABLE agents ADD COLUMN secret_hash TEXT; -- SHA-256 of the agent's secret, hex

CREATE UNIQUE INDEX idx_agents_secret_hash ON agents (secret_hash);

DELETE FROM agents WHERE status = 'pending';
