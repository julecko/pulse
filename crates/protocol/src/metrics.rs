use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Metrics {
    pub cpu: Option<CpuInfo>,
    pub memory: Option<MemoryInfo>,
    pub disks: Vec<DiskInfo>,
    pub linux: Option<LinuxInfo>,
    /// Absent from agents older than this field.
    #[serde(default)]
    pub network: Option<NetworkInfo>,
}

/// A stored snapshot, returned by `GET /agents/{id}/metrics`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MetricsRecord {
    pub id: i64,
    /// When the server received it (UTC, `YYYY-MM-DD HH:MM:SS`).
    pub created_at: String,
    pub metrics: Metrics,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HostInfo {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub arch: String,
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

/// Network traffic the host is handling, averaged over the time since the
/// previous snapshot.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkInfo {
    /// Received over all of `interfaces`, bytes per second.
    pub rx_bytes_per_sec: f64,
    /// Transmitted over all of `interfaces`, bytes per second.
    pub tx_bytes_per_sec: f64,
    /// Every interface except loopback and virtual ones (container veths,
    /// bridges), whose traffic also crosses a real interface and would be
    /// counted twice.
    pub interfaces: Vec<NetworkInterfaceInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkInterfaceInfo {
    pub name: String,
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
    /// Received since the interface came up (or its counters wrapped).
    pub total_rx_bytes: u64,
    /// Transmitted since the interface came up (or its counters wrapped).
    pub total_tx_bytes: u64,
}
