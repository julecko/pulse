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
    pub log: LogConfig,
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
            log: LogConfig::default(),
        }
    }
}
