//! Offline alerts: an alert (and push) when an approved agent sends no
//! metrics for longer than a per-agent limit; resolved when it sends metrics
//! again.

use serde::{Deserialize, Serialize};

/// Shortest settable limit. Agents send metrics every `interval_secs`
/// (default 60), so use a few intervals, or a slow network trips it.
pub const MIN_OFFLINE_AFTER_SECS: u32 = 60;
/// Longest settable limit (30 days).
pub const MAX_OFFLINE_AFTER_SECS: u32 = 30 * 24 * 60 * 60;

/// Returned by `GET /agents/offline-alerts` (every agent) and
/// `PUT /agents/{id}/offline-alert`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineAlertSetting {
    pub agent_id: i64,
    pub hostname: String,
    /// `pending`, `approved` or `revoked`; only approved agents are watched.
    pub status: String,
    /// `None`: not watched (the default).
    pub after_secs: Option<u32>,
    /// UTC, `YYYY-MM-DD HH:MM:SS`; `None` if it never sent any.
    pub last_metrics_at: Option<String>,
    /// It has an active offline alert: it went quiet for longer than
    /// `after_secs` and hasn't sent metrics since.
    pub offline: bool,
}

/// Sent to `PUT /agents/{id}/offline-alert`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetOfflineAlert {
    /// [`MIN_OFFLINE_AFTER_SECS`]-[`MAX_OFFLINE_AFTER_SECS`]; `None` turns
    /// it off (and resolves an active offline alert).
    pub after_secs: Option<u32>,
}
