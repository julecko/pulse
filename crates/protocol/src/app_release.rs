//! Releases of the Android app, served by the server so the app can update
//! itself: `pulse-server-cli app upload` stores an APK, and the app checks
//! `GET /app-releases/latest`, downloads `GET /app-releases/{version_code}/apk`
//! and installs it when its version code is newer than its own.

use serde::{Deserialize, Serialize};

/// Largest Android `versionCode` Google Play accepts; the server takes the
/// same range, from `1`.
pub const MAX_APP_VERSION_CODE: u32 = 2_100_000_000;
pub const MAX_APP_VERSION_NAME_LEN: usize = 64;
pub const MAX_APP_RELEASE_NOTES_LEN: usize = 2000;

/// Returned by `GET /app-releases` (newest first), `GET /app-releases/latest`
/// and `PUT /app-releases/{version_code}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRelease {
    /// The APK's `versionCode`; the highest one is the latest release.
    pub version_code: u32,
    /// The APK's `versionName`, shown to people, e.g. `1.2`.
    pub version_name: String,
    pub notes: Option<String>,
    /// APK size in bytes.
    pub size: u64,
    /// SHA-256 of the APK, lowercase hex; the app checks its download
    /// against it.
    pub sha256: String,
    pub uploaded_by: Option<String>,
    /// UTC, `YYYY-MM-DD HH:MM:SS`.
    pub created_at: String,
}

/// Query of `PUT /app-releases/{version_code}`, whose body is the APK itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAppRelease {
    pub version_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Push "update available" to every registered device (default: yes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify: Option<bool>,
}

/// Whether `name` is an acceptable `versionName`: 1-[`MAX_APP_VERSION_NAME_LEN`]
/// printable ASCII characters, no spaces.
pub fn is_valid_app_version_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_APP_VERSION_NAME_LEN
        && name.bytes().all(|b| b.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_names() {
        assert!(is_valid_app_version_name("1.2"));
        assert!(is_valid_app_version_name("1.2.0-beta+3"));
        assert!(!is_valid_app_version_name(""));
        assert!(!is_valid_app_version_name("1 2"));
        assert!(!is_valid_app_version_name("1.2\n"));
        assert!(!is_valid_app_version_name(
            &"1".repeat(MAX_APP_VERSION_NAME_LEN + 1)
        ));
    }
}
