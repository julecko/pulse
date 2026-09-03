use std::error::Error;
use std::thread;
use std::time::Duration;

use protocol::{CpuInfo, Metrics};

use super::{Collector, Context};

pub struct CpuCollector;

impl Collector for CpuCollector {
    fn name(&self) -> &'static str {
        "cpu"
    }

    fn collect_into(
        &mut self,
        ctx: &mut Context,
        metrics: &mut Metrics,
    ) -> Result<(), Box<dyn Error>> {
        // CPU usage is a delta between two samples.
        ctx.sys.refresh_cpu_usage();
        thread::sleep(Duration::from_millis(200));
        ctx.sys.refresh_cpu_usage();

        let per_core: Vec<f32> = ctx.sys.cpus().iter().map(|c| c.cpu_usage()).collect();

        metrics.cpu = Some(CpuInfo {
            global_usage_percent: ctx.sys.global_cpu_usage(),
            core_count: per_core.len(),
            per_core_usage_percent: per_core,
        });
        Ok(())
    }
}
