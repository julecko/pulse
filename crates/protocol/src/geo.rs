//! Geo alerts: an alert when an SSH login to an agent comes from an IP
//! outside the countries a user allowed, looked up in a MaxMind GeoLite2
//! City database on the server.

use serde::{Deserialize, Serialize};

/// Most countries that can be allowed at once.
pub const MAX_ALLOWED_COUNTRIES: usize = 250;

/// Whether `code` looks like an ISO 3166-1 alpha-2 country code (`SK`,
/// `DE`); uppercase only, the CLI and server normalize first.
pub fn is_valid_country_code(code: &str) -> bool {
    code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase())
}

/// Returned by `GET/PUT /geo-alerts/settings`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoAlertSettings {
    /// ISO codes, e.g. `["SK", "CZ"]`. Empty: geo alerts are off.
    pub allowed_countries: Vec<String>,
    /// Also alert on failed SSH logins, not just successful ones.
    pub include_failures: bool,
    /// Push geo alerts to every registered device.
    pub notify: bool,
    pub updated_by: Option<String>,
    /// UTC, `YYYY-MM-DD HH:MM:SS`.
    pub updated_at: String,
    /// The GeoIP database the server loaded; `None`: none, so no lookups
    /// (and no geo alerts) happen whatever the settings say.
    pub database: Option<GeoDatabaseInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoDatabaseInfo {
    pub path: String,
    /// e.g. `GeoLite2-City`.
    pub database_type: String,
    /// When MaxMind built it (UTC, `YYYY-MM-DD HH:MM:SS`); refresh it
    /// weekly or so, locations change.
    pub built_at: String,
}

/// Sent to `PUT /geo-alerts/settings`; replaces all of them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetGeoAlertSettings {
    pub allowed_countries: Vec<String>,
    pub include_failures: bool,
    pub notify: bool,
}

/// What a geo alert is about, on [`crate::AlertRecord::geo`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoAlertInfo {
    /// `session_open` (a successful login) or `auth_failure`.
    pub kind: String,
    pub ip: String,
    pub user: String,
    /// `None`: the IP isn't in the database.
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_country_codes() {
        assert!(is_valid_country_code("SK"));
        assert!(!is_valid_country_code("sk"));
        assert!(!is_valid_country_code("SVK"));
        assert!(!is_valid_country_code("S1"));
        assert!(!is_valid_country_code(""));
    }
}
