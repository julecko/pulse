mod collector;
mod cpu;
mod disk;
#[cfg(target_os = "linux")]
mod linux;
mod memory;

pub use collector::{Collector, Context};

use protocol::{Metrics, Report};

use crate::host;

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

pub fn collect() -> Report {
    let mut ctx = Context::new();
    let mut metrics = Metrics::default();

    for collector in registry().iter_mut() {
        if let Err(err) = collector.collect_into(&mut ctx, &mut metrics) {
            eprintln!("collector `{}` failed: {err}", collector.name());
        }
    }

    Report::new(host::info(), metrics)
}
