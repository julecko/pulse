use serde::Serialize;
use sysinfo::System;

#[derive(Serialize, Debug)]
pub(crate) struct MemoryInfo {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
}

pub(crate) fn collect() -> MemoryInfo {
    let mut sys = System::new_all();
    sys.refresh_memory();
    MemoryInfo {
        total_bytes: sys.total_memory(),
        used_bytes: sys.used_memory(),
        free_bytes: sys.free_memory(),
        swap_total_bytes: sys.total_swap(),
        swap_used_bytes: sys.used_swap(),
    }
}
