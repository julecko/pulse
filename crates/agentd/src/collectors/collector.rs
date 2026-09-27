use std::error::Error;
use std::time::Instant;

use sysinfo::{CpuRefreshKind, MemoryRefreshKind, Networks, RefreshKind, System};

use protocol::Metrics;

/// State shared by collectors and kept alive between collections, so CPU
/// usage and network traffic can be measured as the change since the
/// previous collection.
pub struct Context {
    pub sys: System,
    pub networks: Networks,
    /// When `networks` was last refreshed.
    pub networks_refreshed_at: Instant,
}

impl Context {
    /// Loads only what the collectors use (CPU usage and memory), not the
    /// process list. This first refresh is also the CPU usage and network
    /// traffic baseline.
    pub fn new() -> Self {
        Self {
            networks: Networks::new_with_refreshed_list(),
            networks_refreshed_at: Instant::now(),
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
