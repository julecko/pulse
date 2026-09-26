use serde::{Deserialize, Serialize};

/// Sent by an agent to `POST /agents/pair`, both to register a brand-new
/// fingerprint and to poll an existing one for approval status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairRequest {
    pub fingerprint: String,
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum PairResponse {
    Pending,
    Approved { token: String },
    Revoked,
}

/// Admin-facing view of an agent, returned by `GET /agents` and `GET /agents/me`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSummary {
    pub id: i64,
    pub fingerprint: String,
    pub hostname: String,
    pub status: String,
    pub created_at: String,
}

/// Returned by `POST /agents/{id}/approve`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveResponse {
    pub token: String,
}

/// Returned by `GET/PUT /agents/pairing`: whether `POST /agents/pair`
/// accepts new agents right now. Already-known agents can always poll.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingStatus {
    pub open: bool,
    /// UTC, `YYYY-MM-DD HH:MM:SS`, when an open window closes by itself;
    /// `None` if it stays open until closed (or it's closed).
    pub open_until: Option<String>,
    pub updated_by: Option<String>,
    pub updated_at: String,
}

/// Sent to `PUT /agents/pairing`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetPairingRequest {
    pub open: bool,
    /// With `open`: close again automatically after this many minutes.
    /// Unset: stay open until closed.
    pub minutes: Option<u32>,
}
