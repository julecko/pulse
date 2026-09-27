use std::collections::HashMap;
use std::error::Error;
use std::os::unix::fs::MetadataExt;

use sysinfo::Disks;

use protocol::{DiskInfo, Metrics};

use super::{Collector, Context};

pub struct DiskCollector;

impl Collector for DiskCollector {
    fn name(&self) -> &'static str {
        "disk"
    }

    fn collect_into(
        &mut self,
        _ctx: &mut Context,
        metrics: &mut Metrics,
    ) -> Result<(), Box<dyn Error>> {
        let disks = Disks::new_with_refreshed_list();
        let mounts = disks.list().iter().map(|d| {
            let info = DiskInfo {
                name: d.name().to_string_lossy().into_owned(),
                mount_point: d.mount_point().to_string_lossy().into_owned(),
                file_system: d.file_system().to_string_lossy().into_owned(),
                total_bytes: d.total_space(),
                available_bytes: d.available_space(),
                removable: d.is_removable(),
            };
            (filesystem_key(&info), info)
        });
        metrics.disks = one_per_filesystem(mounts);
        Ok(())
    }
}

/// What identifies the filesystem behind a mount: its device (`/dev/...`)
/// if it has one, which needs no access to the mount point; else its device
/// ID, since other names are shared by unrelated filesystems (e.g. every
/// Docker `overlay`). `None` if neither is known: then it's reported as its
/// own filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum FsKey {
    Device(String),
    DeviceId(u64),
}

fn filesystem_key(info: &DiskInfo) -> Option<FsKey> {
    if info.name.starts_with("/dev/") {
        return Some(FsKey::Device(info.name.clone()));
    }
    std::fs::metadata(&info.mount_point)
        .ok()
        .map(|m| FsKey::DeviceId(m.dev()))
}

/// Keeps one entry per filesystem (see [`FsKey`]), under its shortest mount
/// point. The mount table lists a filesystem once per place it's mounted:
/// bind mounts (e.g. a directory shared into SFTP chroots) and the agent's
/// own systemd sandbox (`PrivateTmp=` gives it `/tmp` and `/var/tmp`,
/// `ProtectSystem=strict` remounts its state and log dirs), all showing the
/// same space as the filesystem they're on. Keeps the order the filesystems
/// were first seen in.
fn one_per_filesystem(
    mounts: impl IntoIterator<Item = (Option<FsKey>, DiskInfo)>,
) -> Vec<DiskInfo> {
    let mut disks: Vec<DiskInfo> = Vec::new();
    let mut index_by_key: HashMap<FsKey, usize> = HashMap::new();
    for (key, info) in mounts {
        let Some(key) = key else {
            disks.push(info);
            continue;
        };
        match index_by_key.get(&key) {
            Some(&i) => {
                let kept = &disks[i].mount_point;
                if (info.mount_point.len(), &info.mount_point) < (kept.len(), kept) {
                    disks[i] = info;
                }
            }
            None => {
                index_by_key.insert(key, disks.len());
                disks.push(info);
            }
        }
    }
    disks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(name: &str, mount_point: &str) -> DiskInfo {
        DiskInfo {
            name: name.to_string(),
            mount_point: mount_point.to_string(),
            file_system: "ext4".to_string(),
            total_bytes: 100,
            available_bytes: 50,
            removable: false,
        }
    }

    fn dev(name: &str) -> Option<FsKey> {
        Some(FsKey::Device(name.to_string()))
    }

    fn mount_points(disks: &[DiskInfo]) -> Vec<&str> {
        disks.iter().map(|d| d.mount_point.as_str()).collect()
    }

    #[test]
    fn keeps_one_entry_per_filesystem_under_its_shortest_mount_point() {
        let disks = one_per_filesystem([
            (
                dev("/dev/sda3"),
                disk("/dev/sda3", "/srv/sftp/marci/shared"),
            ),
            (dev("/dev/sda3"), disk("/dev/sda3", "/")),
            (dev("/dev/sda2"), disk("/dev/sda2", "/boot")),
            (dev("/dev/sda3"), disk("/dev/sda3", "/tmp")),
            (dev("/dev/sda3"), disk("/dev/sda3", "/var/lib/pulse-agent")),
        ]);
        assert_eq!(mount_points(&disks), ["/", "/boot"]);
    }

    #[test]
    fn same_name_different_filesystems_stay_apart() {
        let disks = one_per_filesystem([
            (
                Some(FsKey::DeviceId(10)),
                disk("overlay", "/var/lib/docker/overlay2/a/merged"),
            ),
            (
                Some(FsKey::DeviceId(11)),
                disk("overlay", "/var/lib/docker/overlay2/b/merged"),
            ),
        ]);
        assert_eq!(disks.len(), 2);
    }

    #[test]
    fn mounts_without_a_key_are_kept() {
        let disks = one_per_filesystem([
            (None, disk("tmpfs", "/mnt/a")),
            (None, disk("tmpfs", "/mnt/b")),
            (dev("/dev/sda3"), disk("/dev/sda3", "/")),
        ]);
        assert_eq!(mount_points(&disks), ["/mnt/a", "/mnt/b", "/"]);
    }
}
