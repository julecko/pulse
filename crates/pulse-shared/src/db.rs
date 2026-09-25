//! Where the server's SQLite file lives, shared by the server (which owns
//! it) and `server-cli users` (which manages accounts in it directly).
//!
//! Absent an explicit `[db] path` in the server config:
//! - debug build: `./data/server.db`, relative to cwd (the repo root
//!   when run via `cargo run` from the workspace root)
//! - release build: `DEFAULT_DATA_DIR/server.db`, matching
//!   `StateDirectory=pulse` in the systemd unit

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Release default data dir; matches `StateDirectory=pulse` in the systemd unit.
pub const DEFAULT_DATA_DIR: &str = "/var/lib/pulse";

/// The server config's `[db]` section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DbConfig {
    /// Explicit database file. Unset: `<data dir>/server.db`.
    pub path: Option<PathBuf>,
}

impl DbConfig {
    pub fn resolved_path(&self) -> PathBuf {
        self.path
            .clone()
            .unwrap_or_else(|| data_dir().join("server.db"))
    }
}

fn data_dir() -> PathBuf {
    if cfg!(debug_assertions) {
        Path::new("data").to_path_buf()
    } else {
        PathBuf::from(DEFAULT_DATA_DIR)
    }
}
