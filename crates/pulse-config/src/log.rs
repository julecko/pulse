//! Tracing setup shared by both binaries.
//!
//! Where lines go, in priority order:
//! - `log.file` in config, if set
//! - otherwise a debug build: stdout (your terminal)
//! - otherwise a release build: `/var/log/pulse/<app>.log`
//!
//! `RUST_LOG` overrides `log.level` whenever it is set.

use std::path::PathBuf;

use serde::Deserialize;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

/// Release default log dir; matches `LogsDirectory=pulse` in the systemd units.
pub const DEFAULT_LOG_DIR: &str = "/var/log/pulse";

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// `error|warn|info|debug|trace`, or any `RUST_LOG`-style filter string.
    pub level: String,
    /// Explicit log file. Unset: stdout in debug, `DEFAULT_LOG_DIR` in release.
    pub file: Option<PathBuf>,
    /// ANSI colours; only applies when writing to a terminal.
    pub ansi: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: None,
            ansi: true,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid log filter {0:?}: {1}")]
    Filter(String, String),
    #[error("creating log dir {}: {source}", .path.display())]
    Dir {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("log file {0} has no file name")]
    BadPath(String),
}

/// Install the global tracing subscriber.
///
/// Keep the returned guard alive for the whole process — dropping it flushes
/// and stops the file-writer thread, so an early drop loses buffered output.
pub fn init(app: &str, cfg: &LogConfig) -> Result<Option<WorkerGuard>, Error> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&cfg.level))
        .map_err(|e| Error::Filter(cfg.level.clone(), e.to_string()))?;

    let file = cfg.file.clone().or_else(|| {
        if cfg!(debug_assertions) {
            None
        } else {
            Some(PathBuf::from(DEFAULT_LOG_DIR).join(format!("{app}.log")))
        }
    });

    match file {
        None => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(cfg.ansi)
                .with_writer(std::io::stdout)
                .init();
            Ok(None)
        }
        Some(path) => {
            let dir = match path.parent() {
                Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
                _ => PathBuf::from("."),
            };
            let name = path
                .file_name()
                .ok_or_else(|| Error::BadPath(path.display().to_string()))?;

            std::fs::create_dir_all(&dir).map_err(|source| Error::Dir {
                path: dir.clone(),
                source,
            })?;

            let (writer, guard) =
                tracing_appender::non_blocking(tracing_appender::rolling::never(&dir, name));
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_writer(writer)
                .init();
            Ok(Some(guard))
        }
    }
}
