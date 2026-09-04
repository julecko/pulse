use serde::{Deserialize, Serialize};

use pulse_config::LogConfig;

/// `server.toml`. See `pulse_config` for where the file is looked up.
#[derive(Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Address the TCP listener binds to, e.g. `0.0.0.0:9000`.
    pub bind: String,
    /// Require mutual TLS 1.3. Certs live next to this file
    /// (`server.crt`, `server.key`, `trusted-agents/`). Managed with
    /// `pulse-server cert ...`.
    pub tls: bool,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub storage: Storage,
    #[serde(default)]
    pub api: Api,
    #[serde(default)]
    pub log: LogConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Api {
    /// Serve the HTTP API for the pulse app (live + history). Requires
    /// `[storage] enabled = true` and at least one account
    /// (`pulse-server user add`).
    pub enabled: bool,
    /// Address the API listener binds to. Keep this on loopback and put a
    /// TLS-terminating reverse proxy in front for remote access.
    pub bind: String,
    /// How long a login session stays valid, in seconds.
    pub session_ttl_secs: u64,
    /// A host counts as "online" if its last report is newer than this many
    /// seconds.
    pub online_secs: u64,
    /// Broadcast buffer for the live SSE stream (reports). A subscriber slower
    /// than this many reports behind is resynced from the latest snapshot.
    pub live_buffer: usize,
}

impl Default for Api {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "127.0.0.1:9100".to_string(),
            session_ttl_secs: 7 * 24 * 3600,
            online_secs: 30,
            live_buffer: 256,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Storage {
    /// Persist every received report to a local SQLite database so history
    /// survives restarts. When false the server keeps only its in-memory view.
    pub enabled: bool,
    /// Database file. Empty => `<state dir>/history.db` (`/var/lib/pulse` under
    /// systemd, next to the executable in debug builds).
    pub path: String,
    /// Days of history to keep; rows older than this are pruned automatically.
    pub retention_days: u32,
    /// How often the pruner runs, in seconds (clamped to a 60s minimum).
    pub prune_interval_secs: u64,
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            enabled: true,
            path: String::new(),
            retention_days: 7,
            prune_interval_secs: 3600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Max connections handled concurrently (0 = unlimited). Excess is dropped.
    pub max_connections: usize,
    /// Max new connections accepted from one source IP per minute (0 = off).
    pub per_ip_per_minute: u32,
    /// Seconds a connection may take to complete the TLS handshake + one report
    /// before it is dropped (0 = no timeout). Guards against slow-loris.
    pub connection_timeout_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            per_ip_per_minute: 600,
            connection_timeout_secs: 15,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:9000".to_string(),
            tls: false,
            limits: Limits::default(),
            storage: Storage::default(),
            api: Api::default(),
            log: LogConfig::default(),
        }
    }
}
