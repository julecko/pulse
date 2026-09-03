//! Persistent history storage.
//!
//! Everything is keyed by `machine_id` — the agent's stable identity. The
//! `hosts` table is the agent registry; every other table (`reports` today,
//! things like `ssh_logins` later) carries a `machine_id` column with a
//! `REFERENCES hosts(machine_id) ON DELETE CASCADE` foreign key, so an agent
//! and all of its data are bound together and removed together.
//!
//! [`SqliteStore`] is blocking. [`StoreHandle`] is the async wrapper callers
//! use: every method runs the blocking work on `tokio::task::spawn_blocking`,
//! so the reactor is never stalled by SQLite.

mod sqlite;

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use protocol::Report;

pub use sqlite::SqliteStore;

/// Milliseconds since the Unix epoch, now.
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("report codec: {0}")]
    Codec(#[from] protocol::ProtocolError),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error(
        "history database schema is newer than this binary (db v{found}, supported v{supported})"
    )]
    SchemaTooNew { found: u32, supported: u32 },
    #[error("storage task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
}

/// One row of the `hosts` table — an agent plus a few denormalised counters.
// Fields are surfaced by the HTTP API (follow-up change) and exercised by tests.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct HostRow {
    pub machine_id: String,
    pub hostname: String,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub kernel_version: Option<String>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub last_peer: Option<String>,
    pub report_count: u64,
}

/// One downsampled time bucket from [`Store::history`].
#[allow(dead_code)] // consumed by the HTTP API (follow-up change)
#[derive(Debug, Clone)]
pub struct Bucket {
    pub ts_ms: u64,
    pub cpu_avg: Option<f64>,
    pub cpu_max: Option<f64>,
    pub mem_used_avg: Option<f64>,
    pub mem_used_max: Option<u64>,
    pub load1_avg: Option<f64>,
    pub samples: u64,
}

/// Blocking storage backend.
pub trait Store: Send + Sync + 'static {
    /// Upsert the host row and append the report. A duplicate `(machine_id,
    /// ts_ms)` is ignored (a retransmit of the same sample).
    fn insert_report(&self, report: &Report, recv_ms: u64, peer: IpAddr) -> Result<(), StoreError>;

    fn list_hosts(&self) -> Result<Vec<HostRow>, StoreError>;

    /// Newest full report for every known host.
    fn latest_per_host(&self) -> Result<Vec<Report>, StoreError>;

    /// Newest full report for one host.
    fn latest_for(&self, machine_id: &str) -> Result<Option<Report>, StoreError>;

    /// Downsampled metrics for `[from_ms, to_ms)`, one row per `bucket_ms` window.
    fn history(
        &self,
        machine_id: &str,
        from_ms: u64,
        to_ms: u64,
        bucket_ms: u64,
    ) -> Result<Vec<Bucket>, StoreError>;

    /// Full reports in `[from_ms, to_ms)`, newest first, capped at `limit`,
    /// returned in chronological order.
    fn recent_reports(
        &self,
        machine_id: &str,
        from_ms: u64,
        to_ms: u64,
        limit: usize,
    ) -> Result<Vec<Report>, StoreError>;

    /// Delete report rows received before `cutoff_recv_ms`. Returns rows removed.
    fn prune(&self, cutoff_recv_ms: u64) -> Result<u64, StoreError>;
}

/// Backend used when `[storage] enabled = false` — accepts everything, keeps
/// nothing.
pub struct NoopStore;

impl Store for NoopStore {
    fn insert_report(&self, _: &Report, _: u64, _: IpAddr) -> Result<(), StoreError> {
        Ok(())
    }
    fn list_hosts(&self) -> Result<Vec<HostRow>, StoreError> {
        Ok(Vec::new())
    }
    fn latest_per_host(&self) -> Result<Vec<Report>, StoreError> {
        Ok(Vec::new())
    }
    fn latest_for(&self, _: &str) -> Result<Option<Report>, StoreError> {
        Ok(None)
    }
    fn history(&self, _: &str, _: u64, _: u64, _: u64) -> Result<Vec<Bucket>, StoreError> {
        Ok(Vec::new())
    }
    fn recent_reports(&self, _: &str, _: u64, _: u64, _: usize) -> Result<Vec<Report>, StoreError> {
        Ok(Vec::new())
    }
    fn prune(&self, _: u64) -> Result<u64, StoreError> {
        Ok(0)
    }
}

/// Async handle over a blocking [`Store`]. Cheap to clone.
#[derive(Clone)]
pub struct StoreHandle {
    inner: Arc<dyn Store>,
    persistent: bool,
}

impl StoreHandle {
    pub fn noop() -> Self {
        Self {
            inner: Arc::new(NoopStore),
            persistent: false,
        }
    }

    /// Open (creating if needed) the SQLite database at `path`, running schema
    /// setup. Creates the parent directory.
    pub fn open_sqlite(path: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            inner: Arc::new(SqliteStore::open(path)?),
            persistent: true,
        })
    }

    /// Whether this handle writes to disk.
    pub fn is_persistent(&self) -> bool {
        self.persistent
    }

    pub async fn insert_report(
        &self,
        report: Arc<Report>,
        recv_ms: u64,
        peer: IpAddr,
    ) -> Result<(), StoreError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || inner.insert_report(&report, recv_ms, peer)).await?
    }

    pub async fn prune(&self, cutoff_recv_ms: u64) -> Result<u64, StoreError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || inner.prune(cutoff_recv_ms)).await?
    }
}

// Read path — consumed by the HTTP API (added in a follow-up change).
#[allow(dead_code)]
impl StoreHandle {
    pub async fn list_hosts(&self) -> Result<Vec<HostRow>, StoreError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || inner.list_hosts()).await?
    }

    pub async fn latest_per_host(&self) -> Result<Vec<Report>, StoreError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || inner.latest_per_host()).await?
    }

    pub async fn latest_for(&self, machine_id: String) -> Result<Option<Report>, StoreError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || inner.latest_for(&machine_id)).await?
    }

    pub async fn history(
        &self,
        machine_id: String,
        from_ms: u64,
        to_ms: u64,
        bucket_ms: u64,
    ) -> Result<Vec<Bucket>, StoreError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || inner.history(&machine_id, from_ms, to_ms, bucket_ms))
            .await?
    }

    pub async fn recent_reports(
        &self,
        machine_id: String,
        from_ms: u64,
        to_ms: u64,
        limit: usize,
    ) -> Result<Vec<Report>, StoreError> {
        let inner = Arc::clone(&self.inner);
        tokio::task::spawn_blocking(move || {
            inner.recent_reports(&machine_id, from_ms, to_ms, limit)
        })
        .await?
    }
}
