use std::error::Error;

use sysinfo::System;

use protocol::{HostInfo, Metrics};

use super::{Collector, Context};

pub struct HostCollector;

impl Collector for HostCollector {
    fn name(&self) -> &'static str {
        "host"
    }

    fn collect_into(
        &mut self,
        _ctx: &mut Context,
        metrics: &mut Metrics,
    ) -> Result<(), Box<dyn Error>> {
        metrics.host = Some(HostInfo {
            hostname: System::host_name().unwrap_or_else(|| "unknown".to_string()),
            os_name: System::name().unwrap_or_else(|| "unknown".to_string()),
            os_version: System::long_os_version().unwrap_or_else(|| "unknown".to_string()),
            kernel_version: System::kernel_version().unwrap_or_else(|| "unknown".to_string()),
            arch: System::cpu_arch(),
        });
        Ok(())
    }
}
