//! Wire contract shared by the agent (producer) and the server (consumer).
//!
//! Everything an agent collects ends up in a single [`Report`]. Each subsystem
//! is its own struct; optional subsystems are `Option<T>` so a report only
//! carries what a given OS could actually produce. Variable-length data
//! (per-core stats, disk lists, ...) is just `Vec<T>` — the serializer handles
//! the length framing, so callers never manage sizes by hand.
//!
//! Module layout:
//! - [`report`]  — the top-level [`Report`] envelope and [`HostInfo`].
//! - [`metrics`] — the [`Metrics`] payload and its per-subsystem structs.
//! - [`frame`]   — length-prefixed MessagePack framing for byte streams.

mod frame;
mod metrics;
mod report;

pub use frame::{ProtocolError, encode, read_report, write_report};
pub use metrics::{CpuInfo, DiskInfo, LinuxInfo, MemoryInfo, Metrics};
pub use report::{HostInfo, Report};

/// Bumped whenever [`Report`] changes shape in a non-additive way.
pub const SCHEMA_VERSION: u16 = 1;

/// Largest message we are willing to buffer from a peer (16 MiB).
pub const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;
