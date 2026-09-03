use std::path::PathBuf;
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
    /// TLS pinning. When present the agent connects with TLS 1.3 and only
    /// proceeds if the server presents exactly this certificate.
    /// Managed with `pulse-agent cert trust <server.crt>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<AgentTls>,
    #[serde(default)]
    pub log: LogConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentTls {
    /// PEM copy of the server's certificate to pin.
    pub cert: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: "127.0.0.1:9000".to_string(),
            interval_secs: 5,
            tls: None,
            log: LogConfig::default(),
        }
    }
}

impl Config {
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.interval_secs)
    }
}
