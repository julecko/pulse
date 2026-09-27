//! Where uploaded Android app releases (APKs) are kept: one file per
//! release in `[app_releases] dir`, named after its version code, with its
//! metadata in the `app_releases` table (see `web::app_releases`).
//!
//! Absent `[app_releases] dir` in the server config:
//! - debug build: `./data/app-releases`
//! - release build: `/var/lib/pulse-server/app-releases`, inside the
//!   systemd unit's `StateDirectory`

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The server config's `[app_releases]` section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppReleasesConfig {
    /// Directory the APKs are stored in. Unset: see the module docs.
    pub dir: Option<PathBuf>,
    /// Largest APK accepted, in MiB.
    pub max_size_mb: u32,
}

impl Default for AppReleasesConfig {
    fn default() -> Self {
        Self {
            dir: None,
            max_size_mb: 200,
        }
    }
}

/// Uploaded files are written here first, then renamed into place.
const UPLOAD_PREFIX: &str = ".upload-";

pub struct AppReleases {
    dir: PathBuf,
    max_size: u64,
}

impl AppReleases {
    /// Creates the directory if needed and deletes uploads a previous run
    /// left half-written.
    pub fn open(cfg: &AppReleasesConfig) -> Result<Self, String> {
        let dir = cfg.dir.clone().unwrap_or_else(|| {
            if cfg!(debug_assertions) {
                PathBuf::from("data/app-releases")
            } else {
                Path::new(pulse_shared::db::DEFAULT_DATA_DIR).join("app-releases")
            }
        });
        std::fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        let entries =
            std::fs::read_dir(&dir).map_err(|e| format!("reading {}: {e}", dir.display()))?;
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(UPLOAD_PREFIX)
            {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        Ok(Self {
            dir,
            max_size: u64::from(cfg.max_size_mb) * 1024 * 1024,
        })
    }

    pub fn max_size(&self) -> u64 {
        self.max_size
    }

    /// The APK of release `version_code`.
    pub fn apk_path(&self, version_code: u32) -> PathBuf {
        self.dir.join(format!("pulse-{version_code}.apk"))
    }

    /// A fresh file name for an upload in progress.
    pub fn upload_path(&self) -> PathBuf {
        let mut nonce = [0u8; 8];
        getrandom(&mut nonce);
        let nonce: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        self.dir.join(format!("{UPLOAD_PREFIX}{nonce}"))
    }
}

fn getrandom(buf: &mut [u8]) {
    use ring::rand::SecureRandom;
    ring::rand::SystemRandom::new()
        .fill(buf)
        .expect("system RNG failed");
}
