use pulse_shared::LogConfig;
use serde::{Deserialize, Serialize};

use crate::app_releases::AppReleasesConfig;
use crate::db::DbConfig;
use crate::db::retention::RetentionConfig;
use crate::geoip::GeoIpConfig;
use crate::push::PushConfig;
use crate::web::WebConfig;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub log: LogConfig,
    pub web: WebConfig,
    pub db: DbConfig,
    pub retention: RetentionConfig,
    pub push: PushConfig,
    pub geoip: GeoIpConfig,
    pub app_releases: AppReleasesConfig,
}
