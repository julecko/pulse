//! Tracing setup shared by both binaries.
//!
//! Where lines go, in priority order:
//! - `log.file` in config, if set
//! - otherwise a debug build: stdout (your terminal)
//! - otherwise a release build: `/var/log/pulse/<app>.log`
//!
//! When writing to a file, `log.rotation` starts a fresh file every day (or
//! hour/minute) and `log.keep_files` prunes the oldest — no `logrotate` needed.
//! Rotation is re-checked on every write, so a process that stays up for weeks
//! rolls over at each period boundary, not just at startup.
//!
//! If the chosen file can't be opened (e.g. run by hand without the systemd
//! `LogsDirectory`), we warn once and fall back to stderr rather than refusing
//! to start.
//!
//! `RUST_LOG` overrides `log.level` whenever it is set.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_appender::rolling::Rotation;
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
    /// How often to start a new file: `daily` | `hourly` | `minutely` | `never`.
    /// Rotated files get a date suffix, e.g. `server.2026-09-03.log`.
    pub rotation: String,
    /// Keep at most this many rotated files, deleting the oldest (0 = keep all).
    /// With `rotation = "daily"` this is roughly the number of days retained.
    pub keep_files: usize,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: None,
            ansi: true,
            rotation: "daily".to_string(),
            keep_files: 10,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid log filter {0:?}: {1}")]
    Filter(String, String),
    #[error("invalid log rotation {0:?} (expected daily|hourly|minutely|never)")]
    Rotation(String),
}

/// Install the global tracing subscriber.
///
/// Keep the returned guard alive for the whole process — dropping it flushes
/// and stops the file-writer thread, so an early drop loses buffered output.
pub fn init(app: &str, cfg: &LogConfig) -> Result<Option<WorkerGuard>, Error> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(&cfg.level))
        .map_err(|e| Error::Filter(cfg.level.clone(), e.to_string()))?;

    let rotation = parse_rotation(&cfg.rotation)?;

    let target = cfg.file.clone().or_else(|| {
        (!cfg!(debug_assertions)).then(|| PathBuf::from(DEFAULT_LOG_DIR).join(format!("{app}.log")))
    });

    if let Some(path) = target {
        match file_writer(&path, rotation, cfg.keep_files) {
            Ok((writer, guard)) => {
                tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_ansi(false)
                    .with_writer(writer)
                    .init();
                return Ok(Some(guard));
            }
            Err(err) => {
                // Opening the configured file failed (e.g. run by hand without
                // the systemd LogsDirectory). Complain, then log to stderr.
                eprintln!(
                    "pulse: cannot open log file {}: {err} — logging to stderr instead",
                    path.display()
                );
                tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .with_ansi(cfg.ansi && std::io::stderr().is_terminal())
                    .with_writer(std::io::stderr)
                    .init();
                return Ok(None);
            }
        }
    }

    // Debug build with no log file configured: straight to the terminal.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(cfg.ansi && std::io::stdout().is_terminal())
        .with_writer(std::io::stdout)
        .init();
    Ok(None)
}

fn parse_rotation(s: &str) -> Result<Rotation, Error> {
    match s.to_ascii_lowercase().as_str() {
        "daily" => Ok(Rotation::DAILY),
        "hourly" => Ok(Rotation::HOURLY),
        "minutely" => Ok(Rotation::MINUTELY),
        "never" | "none" => Ok(Rotation::NEVER),
        _ => Err(Error::Rotation(s.to_string())),
    }
}

/// Rotating non-blocking appender for `path`. Builds eagerly so a permission
/// problem surfaces here (and we can fall back) rather than on the first write.
///
/// `server.log` becomes prefix `server` + suffix `log`, so rotated files read
/// `server.2026-09-03.log`; with `Rotation::NEVER` it stays `server.log`.
fn file_writer(
    path: &Path,
    rotation: Rotation,
    keep_files: usize,
) -> Result<(NonBlocking, WorkerGuard), String> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| "log path has no file name".to_string())?;

    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;

    let mut builder = tracing_appender::rolling::Builder::new().rotation(rotation);
    match file_name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() => {
            builder = builder.filename_prefix(stem).filename_suffix(ext);
        }
        _ => builder = builder.filename_prefix(file_name),
    }
    if keep_files > 0 {
        builder = builder.max_log_files(keep_files);
    }

    let appender = builder
        .build(dir)
        .map_err(|e| format!("opening log in {}: {e}", dir.display()))?;
    Ok(tracing_appender::non_blocking(appender))
}
