use std::error::Error;

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
        metrics.disks = disks
            .list()
            .iter()
            .map(|d| DiskInfo {
                name: d.name().to_string_lossy().into_owned(),
                mount_point: d.mount_point().to_string_lossy().into_owned(),
                file_system: d.file_system().to_string_lossy().into_owned(),
                total_bytes: d.total_space(),
                available_bytes: d.available_space(),
                removable: d.is_removable(),
            })
            .collect();
        Ok(())
    }
}
