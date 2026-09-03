//! Collectors each fill in one slice of [`protocol::Metrics`].
//!
//! They all implement the same [`Collector`] trait and write *into* a shared
//! `Metrics` value rather than returning their own type, so the agent can hold
//! them in one `Vec<Box<dyn Collector>>` and run them in a loop. A collector
//! failing is logged and skipped; it never aborts the whole report.

mod collector;
mod cpu;
mod disk;
mod memory;
#[cfg(target_os = "linux")]
mod linux;

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

/// Run every registered collector and assemble a single [`Report`].
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
