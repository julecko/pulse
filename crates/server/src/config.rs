use pulse_shared::LogConfig;
use serde::{Deserialize, Serialize};

use crate::web::WebConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub log: LogConfig,
    pub web: WebConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            log: LogConfig::default(),
            web: WebConfig::default(),
        }
    }
}
