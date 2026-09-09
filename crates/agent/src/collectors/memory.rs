use std::error::Error;

use protocol::{MemoryInfo, Metrics};

use super::{Collector, Context};

pub struct MemoryCollector;

impl Collector for MemoryCollector {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn collect_into(
        &mut self,
        ctx: &mut Context,
        metrics: &mut Metrics,
    ) -> Result<(), Box<dyn Error>> {
        ctx.sys.refresh_memory();
        metrics.memory = Some(MemoryInfo {
            total_bytes: ctx.sys.total_memory(),
            used_bytes: ctx.sys.used_memory(),
            free_bytes: ctx.sys.free_memory(),
            swap_total_bytes: ctx.sys.total_swap(),
            swap_used_bytes: ctx.sys.used_swap(),
        });
        Ok(())
    }
}
