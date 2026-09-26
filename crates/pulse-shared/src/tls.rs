//! Where the server's TLS cert lives, shared by the server (which serves
//! it) and `pulse-server-cli` (which trusts it by default, so it can verify
//! a self-signed server cert when run on the server host).
//!
//! Absent explicit `[web.tls] cert/key` in the server config:
//! - debug build: `./certs/{cert,key}.pem`, relative to cwd
//! - release build: `DEFAULT_CERT_DIR/{cert,key}.pem`, where the
//!   `pulse-server` package generates a self-signed pair on install

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Release default cert dir.
pub const DEFAULT_CERT_DIR: &str = "/etc/pulse-server/certs";

/// The server config's `[web.tls]` section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    /// Explicit cert file. Unset: `<cert dir>/cert.pem`.
    pub cert: Option<PathBuf>,
    /// Explicit key file. Unset: `<cert dir>/key.pem`.
    pub key: Option<PathBuf>,
}

impl TlsConfig {
    pub fn resolved_cert(&self) -> PathBuf {
        self.cert
            .clone()
            .unwrap_or_else(|| cert_dir().join("cert.pem"))
    }

    pub fn resolved_key(&self) -> PathBuf {
        self.key
            .clone()
            .unwrap_or_else(|| cert_dir().join("key.pem"))
    }
}

fn cert_dir() -> PathBuf {
    if cfg!(debug_assertions) {
        Path::new("certs").to_path_buf()
    } else {
        PathBuf::from(DEFAULT_CERT_DIR)
    }
}
