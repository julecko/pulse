DROP INDEX idx_agents_fingerprint;
ALTER TABLE agents DROP COLUMN token;
ALTER TABLE agents DROP COLUMN status;
ALTER TABLE agents DROP COLUMN fingerprint;
