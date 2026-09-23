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
