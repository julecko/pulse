//! The top-level report envelope: who sent it, when, and what.

use serde::{Deserialize, Serialize};

use crate::{SCHEMA_VERSION, metrics::Metrics};

/// One full sample from one host at one point in time.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Report {
    pub schema_version: u16,
    pub host: HostInfo,
    /// Milliseconds since the Unix epoch, taken when the sample was assembled.
    pub timestamp_unix_ms: u64,
    pub metrics: Metrics,
}

impl Report {
    /// Create a report stamped with the current schema version and wall clock.
    pub fn new(host: HostInfo, metrics: Metrics) -> Self {
        let timestamp_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            schema_version: SCHEMA_VERSION,
            host,
            timestamp_unix_ms,
            metrics,
        }
    }
}

/// Stable-ish identity of the machine the agent runs on.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct HostInfo {
    pub hostname: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub os_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kernel_version: Option<String>,
}
