//! SQLite storage. Where the database file lives is decided by
//! [`pulse_shared::db::DbConfig`], shared with `pulse-server-cli users`.
//!
//! Migrations live in `crates/serverd/migrations/` and are embedded into the
//! binary at compile time, so they apply on startup regardless of cwd. Add a
//! new one with `sqlx migrate add <name>` (run from `crates/server`).

pub mod retention;

use std::path::PathBuf;

pub use pulse_shared::db::DbConfig;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("creating data dir {0}: {1}")]
    CreateDir(PathBuf, std::io::Error),
    #[error("opening database {0}: {1}")]
    Open(PathBuf, sqlx::Error),
    #[error("running migrations: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
}

pub async fn connect(cfg: &DbConfig) -> Result<SqlitePool, DbError> {
    let path = cfg.resolved_path();

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
