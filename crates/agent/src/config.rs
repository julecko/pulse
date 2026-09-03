use std::time::Duration;

use serde::{Deserialize, Serialize};

use pulse_config::LogConfig;

#[derive(Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// `host:port` of the pulse server to ship reports to.
    pub server: String,
    /// How often to collect and send a report.
    pub interval_secs: u64,
    /// Connect with mutual TLS 1.3. Certs live next to this file
    /// (`trusted-server.crt`, `agent.crt`, `agent.key`). Managed with
    /// `pulse-agent cert ...`.
    pub tls: bool,
    #[serde(default)]
    pub log: LogConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: "127.0.0.1:9000".to_string(),
            interval_secs: 5,
            tls: false,
            log: LogConfig::default(),
        }
    }
}

impl Config {
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.interval_secs)
    }
}
