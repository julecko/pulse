//! TOML config loading shared by the `server` and `agent` binaries.
//!
//! Each binary has its own file (`server.toml`, `agent.toml`) resolved by build
//! profile:
//! - debug builds: next to the executable (dev-friendly), falling back to the
//!   working directory.
//! - release builds: `/etc/pulse/<app>.toml`, the systemd-service convention.
//!
//! Either way, `PULSE_<APP>_CONFIG` (e.g. `PULSE_SERVER_CONFIG`) overrides the
//! full path.

pub mod log;
pub mod tls;

use std::path::PathBuf;

use serde::de::DeserializeOwned;

pub use log::LogConfig;

/// Standard release location for config files.
pub const SYSTEM_DIR: &str = "/etc/pulse";

/// Outcome of [`load`]: the parsed config plus where it came from.
pub struct Loaded<T> {
    pub config: T,
    pub path: PathBuf,
    pub found: bool,
}

pub fn path(app: &str) -> PathBuf {
    let env_key = format!("PULSE_{}_CONFIG", app.to_uppercase());
    if let Ok(p) = std::env::var(&env_key) {
        return PathBuf::from(p);
    }

    let filename = format!("{app}.toml");

    if cfg!(debug_assertions) {
        if let Ok(exe) = std::env::current_exe()
            && let Some(dir) = exe.parent()
        {
            return dir.join(filename);
        }
        PathBuf::from(filename)
    } else {
        PathBuf::from(SYSTEM_DIR).join(filename)
    }
}

/// Directory that holds `<app>.toml`.
pub fn dir(app: &str) -> PathBuf {
    path(app)
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Directory that holds this role's TLS material (own cert/key + trusted certs).
///
/// Prefers a dedicated `tls/` subfolder of the config directory. Falls back to
/// the flat config directory when `tls/` does not exist, so deployments created
/// under the old layout keep working until their next `cert` command.
pub fn tls_dir(app: &str) -> PathBuf {
    let nested = dir(app).join("tls");
    if nested.is_dir() { nested } else { dir(app) }
}

pub fn load<T: DeserializeOwned + Default>(app: &str) -> Result<Loaded<T>, Error> {
    let path = path(app);
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let config = toml::from_str(&text).map_err(|source| Error::Parse {
                path: path.clone(),
                source,
            })?;
            Ok(Loaded {
                config,
                path,
                found: true,
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Loaded {
            config: T::default(),
            path,
            found: false,
        }),
        Err(source) => Err(Error::Read { path, source }),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("reading config {}: {source}", .path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing config {}: {source}", .path.display())]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
}
