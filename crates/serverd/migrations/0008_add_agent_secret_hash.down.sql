-- Lossy: secrets can't be recovered from their hashes, so agents lose their
-- credentials and have to be removed and paired again.
DROP INDEX idx_agents_secret_hash;
ALTER TABLE agents DROP COLUMN secret_hash;
UPDATE agents SET status = 'revoked', token = NULL WHERE status = 'approved';
