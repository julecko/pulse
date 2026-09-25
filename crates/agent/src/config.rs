use std::path::{Path, PathBuf};

use pulse_shared::LogConfig;
use serde::{Deserialize, Serialize};

/// Release default socket dir; matches `RuntimeDirectory=pulse` in the systemd unit.
pub const DEFAULT_RUNTIME_DIR: &str = "/run/pulse";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    /// Domain or IP (with port) of the server to send metrics to.
    pub server_addr: String,
    /// How often to collect and send metrics.
    pub interval_secs: u64,
    /// Unix socket `agent pam-hook` reports PAM events to. Unset:
    /// `./data/agent.sock` in debug, `DEFAULT_RUNTIME_DIR/agent.sock` in release.
    pub pam_socket: Option<PathBuf>,
    pub log: LogConfig,
}

impl AgentConfig {
    pub fn pam_socket_path(&self) -> PathBuf {
        self.pam_socket.clone().unwrap_or_else(|| {
            let dir = if cfg!(debug_assertions) {
                Path::new("data").to_path_buf()
            } else {
                PathBuf::from(DEFAULT_RUNTIME_DIR)
            };
            dir.join("agent.sock")
        })
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:8080".to_string(),
            interval_secs: 60,
            pam_socket: None,
            log: LogConfig::default(),
        }
    }
}
