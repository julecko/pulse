//! Module layout:
//! - [`report`]  — the top-level [`Report`] envelope and [`HostInfo`].
//! - [`metrics`] — the [`Metrics`] payload and its per-subsystem structs.
//! - [`frame`]   — length-prefixed MessagePack framing for byte streams.

mod frame;
mod metrics;
mod report;

pub use frame::{ProtocolError, decode_body, encode, encode_body, read_report, write_report};
#[cfg(feature = "async")]
pub use frame::{read_report_async, write_report_async};
pub use metrics::{CpuInfo, DiskInfo, LinuxInfo, MemoryInfo, Metrics};
pub use report::{HostInfo, Report};

/// Bumped whenever [`Report`] changes shape in a non-additive way.
pub const SCHEMA_VERSION: u16 = 1;

/// Largest message we are willing to buffer from a peer (16 MiB).
pub const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;
