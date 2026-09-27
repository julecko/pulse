-- Network traffic (protocol::NetworkInfo); NULL for snapshots from agents
-- that don't report it.
ALTER TABLE metrics ADD COLUMN network_rx_bytes_per_sec REAL;
ALTER TABLE metrics ADD COLUMN network_tx_bytes_per_sec REAL;
-- JSON array of {name, rx_bytes_per_sec, tx_bytes_per_sec, total_rx_bytes, total_tx_bytes}
ALTER TABLE metrics ADD COLUMN network_interfaces TEXT;
