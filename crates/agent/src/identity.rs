//! Local agent identity: a random fingerprint generated once on first run
//! and persisted, plus the bearer token issued once the server approves it.

use std::path::{Path, PathBuf};

use protocol::HostInfo;
use serde::{Deserialize, Serialize};
use sysinfo::System;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub fingerprint: Uuid,
    pub token: Option<String>,
}

fn state_path() -> PathBuf {
    let dir = if cfg!(debug_assertions) {
        Path::new("data").to_path_buf()
    } else {
        PathBuf::from("/var/lib/pulse")
    };
    dir.join("identity.toml")
}

/// Loads the persisted identity, or generates and saves a fresh one if none
/// exists yet (or the existing file fails to parse).
pub fn load_or_create() -> Identity {
    let path = state_path();

    if let Ok(contents) = std::fs::read_to_string(&path)
        && let Ok(identity) = toml::from_str(&contents)
    {
        return identity;
    }

    let identity = Identity {
        fingerprint: Uuid::new_v4(),
        token: None,
    };
    save(&identity);
    identity
}

/// Host-identifying info sent alongside the fingerprint when pairing. Not
/// part of the periodic `Metrics` collection since it rarely changes.
pub fn host_info() -> HostInfo {
    HostInfo {
        hostname: System::host_name().unwrap_or_else(|| "unknown".to_string()),
        os_name: System::name().unwrap_or_else(|| "unknown".to_string()),
        os_version: System::long_os_version().unwrap_or_else(|| "unknown".to_string()),
        kernel_version: System::kernel_version().unwrap_or_else(|| "unknown".to_string()),
        arch: System::cpu_arch(),
    }
}

pub fn save(identity: &Identity) {
    let path = state_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(contents) = toml::to_string_pretty(identity) {
        let _ = std::fs::write(&path, contents);
    }
}
