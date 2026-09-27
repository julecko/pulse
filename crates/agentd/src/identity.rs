//! Local agent identity, generated once on first run and persisted:
//! - `secret`: 32 random bytes (hex). Sent with every pairing poll to prove
//!   this agent owns its fingerprint, and used as the bearer token once the
//!   server approves it. Only its SHA-256 is stored on the server.
//! - `fingerprint`: derived from the secret
//!   ([`protocol::agent_fingerprint`]). Public; it's what an admin compares
//!   before approving (`pulse-agentd fingerprint`).
//!
//! The file is mode 0600, readable only by the agent's own user.
//!
//! `pulse-agentd fingerprint` / `reset-identity` are run as root (via sudo),
//! in a state dir the agent's user owns. So every path in it is treated as
//! attacker-controlled: symlinks are never followed, and the temp file is
//! freshly created under a random name, so a compromised agent user can't
//! make root read, write or chown some other file (e.g. `/etc/shadow`).

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use protocol::HostInfo;
use serde::{Deserialize, Serialize};
use sysinfo::System;

/// Release default state dir; matches `StateDirectory=pulse-agent` in the systemd unit.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/pulse-agent";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub fingerprint: String,
    pub secret: String,
}

/// The file as stored, including the format from before secrets existed:
/// a random UUID `fingerprint` plus the `token` the server handed out on
/// approval.
#[derive(Deserialize)]
struct StoredIdentity {
    fingerprint: Option<String>,
    secret: Option<String>,
    token: Option<String>,
}

fn state_path() -> PathBuf {
    let dir = if cfg!(debug_assertions) {
        Path::new("data").to_path_buf()
    } else {
        PathBuf::from(DEFAULT_STATE_DIR)
    };
    dir.join("identity.toml")
}

/// Loads the persisted identity, or generates and saves a fresh one if
/// there's none yet.
///
/// An old-format file from an approved agent is converted: its token
/// becomes its secret (the server migrated the token's hash the same way),
/// so the agent stays approved. One without a token (never approved) gets a
/// fresh identity; the server dropped its pending request anyway.
pub fn load_or_create() -> Result<Identity, String> {
    let path = state_path();
    let stored = match read_no_follow(&path) {
        Ok(contents) => Some(
            toml::from_str::<StoredIdentity>(&contents)
                .map_err(|e| format!("parsing {}: {e}", path.display()))?,
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("reading {}: {e}", path.display())),
    };

    let identity = match stored {
        Some(StoredIdentity {
            fingerprint: Some(fingerprint),
            secret: Some(secret),
            ..
        }) => {
            return Ok(Identity {
                fingerprint,
                secret,
            });
        }
        Some(StoredIdentity {
            fingerprint: Some(fingerprint),
            secret: None,
            token: Some(token),
        }) => {
            tracing::info!(
                "converting identity from before agent secrets; the old token becomes the secret"
            );
            Identity {
                fingerprint,
                secret: token,
            }
        }
        _ => generate()?,
    };
    save(&identity)?;
    Ok(identity)
}

/// Replaces the identity with a freshly generated one and returns it.
pub fn reset() -> Result<Identity, String> {
    let identity = generate()?;
    save(&identity)?;
    Ok(identity)
}

fn generate() -> Result<Identity, String> {
    let mut bytes = [0u8; protocol::AGENT_SECRET_LEN / 2];
    getrandom::fill(&mut bytes).map_err(|e| format!("generating agent secret: {e}"))?;
    let secret: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(Identity {
        fingerprint: protocol::agent_fingerprint(&secret),
        secret,
    })
}

/// Reads `path` without following a symlink (`ELOOP` if it is one), and
/// only if it's a regular file (`O_NONBLOCK` so a FIFO can't hang us).
fn read_no_follow(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

/// Atomically replaces the identity file (mode 0600). When written by root
/// (`pulse-agentd reset-identity`), the file is handed to the state dir's
/// owner, the agent's user, so the daemon can read it. If the dir doesn't
/// exist yet it's created root-owned, and systemd's `StateDirectory=` hands
/// it and its contents to the agent's user on the daemon's first start.
///
/// The temp file gets a random name and is created exclusively
/// (`O_CREAT | O_EXCL`, which never follows symlinks), so the file we
/// write and chown is always one we just created ourselves.
fn save(identity: &Identity) -> Result<(), String> {
    let path = state_path();
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let contents = toml::to_string_pretty(identity).map_err(|e| e.to_string())?;
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).map_err(|e| format!("generating temp file name: {e}"))?;
    let suffix: String = suffix.iter().map(|b| format!("{b:02x}")).collect();
    let tmp = path.with_extension(format!("toml.{suffix}.tmp"));

    let write = || -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        let owner = std::fs::metadata(dir)?;
        if owner.uid() != file.metadata()?.uid() {
            std::os::unix::fs::fchown(&file, Some(owner.uid()), Some(owner.gid()))?;
        }
        std::fs::rename(&tmp, &path)
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("writing {}: {e}", path.display())
    })
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
