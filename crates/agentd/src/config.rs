use std::path::PathBuf;

use pulse_shared::LogConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    /// Domain or IP (with port) of the server to send metrics to.
    pub server_addr: String,
    /// How often to collect and send metrics.
    pub interval_secs: u64,
    /// Certificate (PEM) to pin for the server: if set, it's the only one
    /// trusted, replacing the built-in public CA roots. Set this to the
    /// server's own `cert.pem` when it uses a self-signed cert (or to your
    /// private CA's cert). The server's cert is always verified; there is
    /// no way to turn that off.
    pub ca_cert: Option<PathBuf>,
    /// Unix socket `pulse-agent-cli pam-hook` reports PAM events to (and
    /// `pulse-agent-cli notify` sends notifications through). Unset:
    /// see [`pulse_shared::agent::pam_socket_path`].
    pub pam_socket: Option<PathBuf>,
    pub log: LogConfig,
}

impl AgentConfig {
    pub fn pam_socket_path(&self) -> PathBuf {
        pulse_shared::agent::pam_socket_path(self.pam_socket.as_deref())
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:8080".to_string(),
            interval_secs: 60,
            ca_cert: None,
            pam_socket: None,
            log: LogConfig::default(),
        }
    }
}
