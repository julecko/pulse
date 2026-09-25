//! SQLite storage.
//!
//! Where the database file lives, absent an explicit config override:
//! - debug build: `./data/server.db`, relative to cwd (the repo root
//!   when run via `cargo run` from the workspace root)
//! - release build: `DEFAULT_DATA_DIR/server.db`, matching
//!   `StateDirectory=pulse` in the systemd unit
//!
//! Migrations live in `crates/server/migrations/` and are embedded into the
//! binary at compile time, so they apply on startup regardless of cwd. Add a
//! new one with `sqlx migrate add <name>` (run from `crates/server`).

pub mod retention;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};

/// Release default data dir; matches `StateDirectory=pulse` in the systemd unit.
pub const DEFAULT_DATA_DIR: &str = "/var/lib/pulse";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DbConfig {
    /// Explicit database file. Unset: `<data dir>/server.db`.
    pub path: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("creating data dir {0}: {1}")]
    CreateDir(PathBuf, std::io::Error),
    #[error("opening database {0}: {1}")]
    Open(PathBuf, sqlx::Error),
    #[error("running migrations: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

fn data_dir() -> PathBuf {
    if cfg!(debug_assertions) {
        Path::new("data").to_path_buf()
    } else {
        PathBuf::from(DEFAULT_DATA_DIR)
    }
}

pub async fn connect(cfg: &DbConfig) -> Result<SqlitePool, DbError> {
    let path = cfg
        .path
        .clone()
        .unwrap_or_else(|| data_dir().join("server.db"));

    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|e| DbError::CreateDir(dir.to_path_buf(), e))?;
    }

    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true);

    let pool = SqlitePoolOptions::new()
        .connect_with(options)
        .await
        .map_err(|e| DbError::Open(path.clone(), e))?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    tracing::info!(path = %path.display(), "database ready");

    Ok(pool)
}
