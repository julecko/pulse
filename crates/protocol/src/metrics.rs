use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Metrics {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cpu: Option<CpuInfo>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub memory: Option<MemoryInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub disks: Vec<DiskInfo>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub linux: Option<LinuxInfo>,
}

impl Metrics {
    pub fn section_count(&self) -> usize {
        self.cpu.is_some() as usize
            + self.memory.is_some() as usize
            + (!self.disks.is_empty()) as usize
            + self.linux.is_some() as usize
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CpuInfo {
    pub global_usage_percent: f32,
    pub per_core_usage_percent: Vec<f32>,
    pub core_count: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiskInfo {
    pub name: String,
    pub mount_point: String,
    pub file_system: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub removable: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LinuxInfo {
    pub load_avg_one: f64,
    pub load_avg_five: f64,
    pub load_avg_fifteen: f64,
    pub uptime_secs: u64,
}
