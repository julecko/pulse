use std::error::Error;

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
        // sysinfo reports usage since the previous refresh, and `ctx` lives
        // across collections, so this is the average over the whole interval
        // since the last snapshot (or since `Context::new` for the first).
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
