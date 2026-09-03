use std::error::Error;

use sysinfo::System;

use protocol::{LinuxInfo, Metrics};

use super::{Collector, Context};

/// Linux-only extras. Only added to the registry on `target_os = "linux"`.
pub struct LinuxCollector;

impl Collector for LinuxCollector {
    fn name(&self) -> &'static str {
        "linux"
    }

    fn collect_into(
        &mut self,
        _ctx: &mut Context,
        metrics: &mut Metrics,
    ) -> Result<(), Box<dyn Error>> {
        let load = System::load_average();
        metrics.linux = Some(LinuxInfo {
            load_avg_one: load.one,
            load_avg_five: load.five,
            load_avg_fifteen: load.fifteen,
            uptime_secs: System::uptime(),
        });
        Ok(())
    }
}
