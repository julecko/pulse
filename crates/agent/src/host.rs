use std::fs;
use std::io::Read;
use std::path::PathBuf;

use sysinfo::System;

use protocol::HostInfo;

pub fn info() -> HostInfo {
    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());
    HostInfo {
        machine_id: machine_id(&hostname),
        hostname,
        os: System::name(),
        os_version: System::os_version(),
        kernel_version: System::kernel_version(),
    }
}

fn machine_id(hostname: &str) -> String {
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Some(id) = fs::read_to_string(path).ok().map(|s| s.trim().to_owned())
            && !id.is_empty()
        {
            return id;
        }
    }

    if let Some(path) = persisted_id_path() {
        if let Some(id) = fs::read_to_string(&path).ok().map(|s| s.trim().to_owned())
            && !id.is_empty()
        {
            return id;
        }
        if let Some(id) = random_id() {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&path, &id);
            return id;
        }
    }

    format!("host-{hostname}")
}

fn persisted_id_path() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("XDG_STATE_HOME") {
        return Some(PathBuf::from(dir).join("pulse/machine-id"));
    }
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".local/state/pulse/machine-id"))
}

fn random_id() -> Option<String> {
    let mut buf = [0u8; 16];
    fs::File::open("/dev/urandom")
        .ok()?
        .read_exact(&mut buf)
        .ok()?;
    Some(buf.iter().map(|b| format!("{b:02x}")).collect())
}
