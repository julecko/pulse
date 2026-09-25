use std::error::Error;

use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

use protocol::Metrics;

/// State shared by collectors and kept alive between collections, so CPU
/// usage can be measured as the change since the previous collection.
pub struct Context {
    pub sys: System,
}

impl Context {
    /// Loads only what the collectors use (CPU usage and memory), not the
    /// process list. This first refresh is also the CPU usage baseline.
    pub fn new() -> Self {
        Self {
            sys: System::new_with_specifics(
                RefreshKind::nothing()
                    .with_cpu(CpuRefreshKind::nothing().with_cpu_usage())
                    .with_memory(MemoryRefreshKind::everything()),
            ),
        }
    }
}

pub trait Collector {
    fn name(&self) -> &'static str;

    fn collect_into(
        &mut self,
        ctx: &mut Context,
        metrics: &mut Metrics,
    ) -> Result<(), Box<dyn Error>>;
}
