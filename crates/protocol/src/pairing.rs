use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Length of an agent secret: 32 random bytes, hex-encoded.
pub const AGENT_SECRET_LEN: usize = 64;

/// The public fingerprint for an agent secret: the first 16 bytes of
/// `SHA-256("pulse-agent-id:" + secret)`, hex-encoded (32 chars).
///
/// Binding the fingerprint to the secret means nobody can register someone
/// else's fingerprint with a different secret, and comparing fingerprints
/// before approving really does compare credentials. The fingerprint is
/// public; knowing it grants nothing.
pub fn agent_fingerprint(secret: &str) -> String {
    let digest = Sha256::digest(format!("pulse-agent-id:{secret}"));
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

/// Whether `secret` has the shape agents generate: [`AGENT_SECRET_LEN`]
/// lowercase hex characters.
pub fn is_valid_agent_secret(secret: &str) -> bool {
    secret.len() == AGENT_SECRET_LEN
        && secret
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Sent by an agent to `POST /agents/pair`, both to register a brand-new
/// fingerprint and to poll an existing one for approval status.
///
/// `secret` proves the agent owns `fingerprint`: the server stores only its
/// SHA-256, and a new fingerprint must equal [`agent_fingerprint`] of it.
/// Once approved, the same secret is the agent's bearer token on the
/// `/agents/me/...` routes; the server never sends a credential back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairRequest {
    pub fingerprint: String,
    pub secret: String,
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub arch: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum PairResponse {
    Pending,
    /// The agent's secret is accepted as its bearer token.
    Approved,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_bound_to_the_secret() {
        let a = "0".repeat(AGENT_SECRET_LEN);
        let b = "1".repeat(AGENT_SECRET_LEN);
        assert_eq!(agent_fingerprint(&a), agent_fingerprint(&a));
        assert_ne!(agent_fingerprint(&a), agent_fingerprint(&b));
        assert_eq!(agent_fingerprint(&a).len(), 32);
    }

    #[test]
    fn validates_secret_shape() {
        assert!(is_valid_agent_secret(&"ab".repeat(32)));
        assert!(!is_valid_agent_secret(&"AB".repeat(32)));
        assert!(!is_valid_agent_secret(&"ab".repeat(31)));
        assert!(!is_valid_agent_secret(&"zz".repeat(32)));
    }
}
