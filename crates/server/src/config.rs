use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use pulse_config::LogConfig;

/// `server.toml`. See `pulse_config` for where the file is looked up.
#[derive(Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Address the TCP listener binds to, e.g. `0.0.0.0:9000`.
    pub bind: String,
    /// TLS material. When present the listener only accepts TLS 1.3.
    /// Managed with `pulse-server cert generate`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<ServerTls>,
    #[serde(default)]
    pub log: LogConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerTls {
    /// PEM certificate (chain) the server presents.
    pub cert: PathBuf,
    /// PEM private key for `cert`.
    pub key: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:9000".to_string(),
            tls: None,
            log: LogConfig::default(),
        }
    }
}
