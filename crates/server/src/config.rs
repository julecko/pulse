use serde::{Deserialize, Serialize};

use pulse_config::LogConfig;

/// `server.toml`. See `pulse_config` for where the file is looked up.
#[derive(Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Address the TCP listener binds to, e.g. `0.0.0.0:9000`.
    pub bind: String,
    #[serde(default)]
    pub log: LogConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:9000".to_string(),
            log: LogConfig::default(),
        }
    }
}
