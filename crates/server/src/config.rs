use pulse_shared::LogConfig;
use serde::{Deserialize, Serialize};

use crate::db::DbConfig;
use crate::db::retention::RetentionConfig;
use crate::web::WebConfig;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub log: LogConfig,
    pub web: WebConfig,
    pub db: DbConfig,
    pub retention: RetentionConfig,
}
