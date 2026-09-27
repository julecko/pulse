-- Retention prunes auth_events by created_at (server receive time), not the
-- agent-supplied occurred_at, which a misbehaving agent could date far into
-- the future to dodge pruning.
CREATE INDEX idx_auth_events_created_at ON auth_events (created_at);
