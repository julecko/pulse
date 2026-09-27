DROP TABLE offline_alerts;
ALTER TABLE agents DROP COLUMN offline_after_set_at;
ALTER TABLE agents DROP COLUMN offline_after_secs;
ALTER TABLE agents DROP COLUMN last_metrics_at;
