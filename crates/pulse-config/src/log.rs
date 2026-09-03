//! Tracing setup shared by both binaries.
//!
//! Where lines go, in priority order:
//! - `log.file` in config, if set
//! - otherwise a debug build: stderr (your terminal)
//! - otherwise a release build: `/var/log/pulse/<app>.log`
//!
//! If the chosen file can't be opened (e.g. run by hand without the systemd
//! `LogsDirectory`), we warn once and fall back to stderr rather than refusing
//! to start.
//!
//! `RUST_LOG` overrides `log.level` whenever it is set.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_subscriber::EnvFilter;

/// Release default log dir; matches `LogsDirectory=pulse` in the systemd units.
pub const DEFAULT_LOG_DIR: &str = "/var/log/pulse";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// `error|warn|info|debug|trace`, or any `RUST_LOG`-style filter string.
    pub level: String,
    /// Explicit log file. Unset: stderr in debug, `DEFAULT_LOG_DIR` in release.
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
}

/// Install the global tracing subscriber.
///
/// Keep the returned guard alive for the whole process — dropping it flushes
/// and stops the file-writer thread, so an early drop loses buffered output.
pub fn init(app: &str, cfg: &LogConfig) -> Result<Option<WorkerGuard>, Error> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&cfg.level))
        .map_err(|e| Error::Filter(cfg.level.clone(), e.to_string()))?;

    let target = cfg.file.clone().or_else(|| {
        (!cfg!(debug_assertions)).then(|| PathBuf::from(DEFAULT_LOG_DIR).join(format!("{app}.log")))
    });

    if let Some(path) = target {
        match file_writer(&path) {
            Ok((writer, guard)) => {
                tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_ansi(false)
                    .with_writer(writer)
                    .init();
                return Ok(Some(guard));
            }
            Err(err) => {
                eprintln!(
                    "pulse: cannot open log file {}: {err} — logging to stderr instead",
                    path.display()
                );
            }
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(cfg.ansi)
        .with_writer(std::io::stderr)
        .init();
    Ok(None)
}

/// Non-blocking appender for `path`. Opens the file up front so a permission
/// problem surfaces here (and we can fall back) rather than on the first write.
fn file_writer(path: &Path) -> std::io::Result<(NonBlocking, WorkerGuard)> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "log path has no file name",
        )
    })?;

    std::fs::create_dir_all(dir)?;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;

    Ok(tracing_appender::non_blocking(
        tracing_appender::rolling::never(dir, name),
    ))
}
