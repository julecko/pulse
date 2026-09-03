use std::time::Duration;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// `host:port` of the pulse server to ship reports to.
    pub server: String,
    /// How often to collect and send a report.
    pub interval_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: "127.0.0.1:9000".to_string(),
            interval_secs: 5,
        }
    }
}

impl Config {
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.interval_secs)
    }
}
