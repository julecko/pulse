//! Generic TOML config loading shared by both binaries.
//!
//! Each binary defines its own config struct (e.g. `AgentConfig`) with
//! `#[serde(default)]` plus a `Default` impl, then calls [`load`]. A missing
//! file is not an error — you get `T::default()` back; a file that exists but
//! fails to parse is.
//!
//! Where the file is read from, in priority order:
//! - `PULSE_CONFIG` env var, if set
//! - release build: `/etc/pulse/<app>.toml`
//! - debug build: `./config/<app>.toml` (the repo's checked-in `config/` dir,
//!   when run from the workspace root)

use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;

/// Release default config dir.
pub const DEFAULT_CONFIG_DIR: &str = "/etc/pulse";

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading config {0}: {1}")]
    Read(PathBuf, std::io::Error),
    #[error("parsing config {0}: {1}")]
    Parse(PathBuf, toml::de::Error),
}

/// Config path for `app`, absent an explicit `PULSE_CONFIG` override.
pub fn default_path(app: &str) -> PathBuf {
    if let Ok(path) = std::env::var("PULSE_CONFIG") {
        return PathBuf::from(path);
    }
    if cfg!(debug_assertions) {
        Path::new("config").join(format!("{app}.toml"))
    } else {
        Path::new(DEFAULT_CONFIG_DIR).join(format!("{app}.toml"))
    }
}

/// Load `T` for `app` from [`default_path`]. Missing file falls back to `T::default()`.
pub fn load<T: DeserializeOwned + Default>(app: &str) -> Result<T, ConfigError> {
    load_from(&default_path(app))
}

/// Load `T` from an explicit path. Missing file falls back to `T::default()`.
pub fn load_from<T: DeserializeOwned + Default>(path: &Path) -> Result<T, ConfigError> {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            toml::from_str(&contents).map_err(|e| ConfigError::Parse(path.to_path_buf(), e))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(ConfigError::Read(path.to_path_buf(), e)),
    }
}
