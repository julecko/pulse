CREATE TABLE metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),

    -- cpu
    cpu_global_usage_percent REAL,
    cpu_per_core_usage_percent TEXT, -- JSON array of f32
    cpu_core_count INTEGER,

    -- memory
    memory_total_bytes INTEGER,
    memory_used_bytes INTEGER,
    memory_free_bytes INTEGER,
    memory_swap_total_bytes INTEGER,
    memory_swap_used_bytes INTEGER,

    -- disks (Vec<DiskInfo>)
    disks TEXT NOT NULL DEFAULT '[]', -- JSON array of {name, mount_point, file_system, total_bytes, available_bytes, removable}

    -- linux-only
    linux_load_avg_one REAL,
    linux_load_avg_five REAL,
    linux_load_avg_fifteen REAL,
    linux_uptime_secs INTEGER
);

CREATE INDEX idx_metrics_agent_id_collected_at ON metrics (agent_id, created_at);
