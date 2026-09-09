mod collector;
mod cpu;
mod memory;

pub use collector::{Collector, Context};

use protocol::Metrics;

fn registry() -> Vec<Box<dyn Collector>> {
    let collectors: Vec<Box<dyn Collector>> = vec![
        Box::new(cpu::CpuCollector),
        Box::new(memory::MemoryCollector),
    ];

    collectors
}

pub fn collect() -> Metrics {
    let mut ctx = Context::new();
    let mut metrics = Metrics::default();

    for collector in registry().iter_mut() {
        if let Err(err) = collector.collect_into(&mut ctx, &mut metrics) {
            eprintln!(
                "WARN collector failed: collector={} err={}",
                collector.name(),
                err
            );
        }
    }

    metrics
}
