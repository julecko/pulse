//! Where the server's SQLite file lives, shared by the server (which owns
//! it) and `pulse-server-cli users` (which manages accounts in it directly).
//!
//! Absent an explicit `[db] path` in the server config:
//! - debug build: `./data/server.db`, relative to cwd (the repo root
//!   when run via `cargo run` from the workspace root)
//! - release build: `DEFAULT_DATA_DIR/server.db`, matching
//!   `StateDirectory=pulse-server` in the `pulse-serverd` systemd unit

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Release default data dir; matches `StateDirectory=pulse-server` in the systemd unit.
pub const DEFAULT_DATA_DIR: &str = "/var/lib/pulse-server";

/// sqlx's own default pool size, used when `[db] max_connections` is unset.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 10;

/// The server config's `[db]` section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DbConfig {
    /// Explicit database file. Unset: `<data dir>/server.db`.
    pub path: Option<PathBuf>,
    /// Max SQLite connections in the pool. Unset: `DEFAULT_MAX_CONNECTIONS`.
    /// Raise it on a busy server with many agents/users hitting the API at
    /// once; lower it on a small box to trim idle per-connection page-cache
    /// memory (~2 MiB each by default).
    pub max_connections: Option<u32>,
}

impl DbConfig {
    pub fn resolved_path(&self) -> PathBuf {
        self.path
            .clone()
            .unwrap_or_else(|| data_dir().join("server.db"))
    }

    pub fn resolved_max_connections(&self) -> u32 {
        self.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS)
    }
}

fn data_dir() -> PathBuf {
    if cfg!(debug_assertions) {
        Path::new("data").to_path_buf()
    } else {
        PathBuf::from(DEFAULT_DATA_DIR)
    }
}
