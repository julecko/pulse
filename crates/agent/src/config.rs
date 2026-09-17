use pulse_shared::LogConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    /// Domain or IP (with port) of the server to send metrics to.
    pub server_addr: String,
    /// How often to collect and send metrics.
    pub interval_secs: u64,
    pub log: LogConfig,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:8080".to_string(),
            interval_secs: 60,
            log: LogConfig::default(),
        }
    }
}
