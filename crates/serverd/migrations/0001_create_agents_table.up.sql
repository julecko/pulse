CREATE TABLE agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL, -- not unique: hosts may share a name
    public_ip TEXT NOT NULL,
    os_name TEXT NOT NULL,
    os_version TEXT NOT NULL,
    kernel_version TEXT NOT NULL,
    arch TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
