use serde::Serialize;
use std::thread;
use std::time::Duration;
use sysinfo::System;

#[derive(Serialize, Debug)]
pub(crate) struct CpuInfo {
    pub global_usage_percent: f32,
    pub per_core_usage_percent: Vec<f32>,
    pub core_count: usize,
}

pub(crate) fn collect() -> CpuInfo {
    let mut sys = System::new_all();

    // Need two samples to compute a usage delta
    sys.refresh_cpu_usage();
    thread::sleep(Duration::from_millis(200));
    sys.refresh_cpu_usage();

    let per_core: Vec<f32> = sys.cpus().iter().map(|cpu| cpu.cpu_usage()).collect();

    CpuInfo {
        global_usage_percent: sys.global_cpu_usage(),
        core_count: per_core.len(),
        per_core_usage_percent: per_core,
    }
}
