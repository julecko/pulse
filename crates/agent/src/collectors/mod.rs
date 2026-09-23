mod collector;
mod cpu;
mod disk;
mod linux;
mod memory;

pub use collector::{Collector, Context};

use protocol::Metrics;

fn registry() -> Vec<Box<dyn Collector>> {
    let mut collectors: Vec<Box<dyn Collector>> = vec![
        Box::new(cpu::CpuCollector),
        Box::new(memory::MemoryCollector),
        Box::new(disk::DiskCollector),
    ];

    #[cfg(target_os = "linux")]
    collectors.push(Box::new(linux::LinuxCollector));

    collectors
}

pub fn collect() -> Metrics {
    let mut ctx = Context::new();
    let mut metrics = Metrics::default();

    for collector in registry().iter_mut() {
        let name = collector.name();
        match collector.collect_into(&mut ctx, &mut metrics) {
            Ok(()) => tracing::debug!(collector = name, "collected"),
            Err(err) => tracing::warn!(collector = name, %err, "collector failed"),
        }
    }

    metrics
}
