use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthEventKind {
    SessionOpen,
    SessionClose,
    AuthFailure,
}

impl AuthEventKind {
    pub const ALL: [Self; 3] = [Self::SessionOpen, Self::SessionClose, Self::AuthFailure];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SessionOpen => "session_open",
            Self::SessionClose => "session_close",
            Self::AuthFailure => "auth_failure",
        }
    }
}

impl fmt::Display for AuthEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

impl FromStr for AuthEventKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| {
                let names: Vec<_> = Self::ALL.iter().map(|k| k.as_str()).collect();
                format!(
                    "unknown PAM event kind {s:?} (expected one of: {})",
                    names.join(", ")
                )
            })
    }
}

/// A PAM event captured on the agent's host by `pulse-agent-cli pam-hook`, forwarded
/// one at a time to `POST /agents/me/auth-events`. The owning agent is taken
/// from the bearer token, never from the payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEvent {
    pub kind: AuthEventKind,
    /// `PAM_SERVICE`: sshd, sudo, su, login, ...
    pub service: String,
    /// `PAM_USER`: the account being authenticated / logged into.
    pub user: String,
    /// `PAM_RUSER`: requesting user, e.g. the invoking user for sudo.
    pub ruser: Option<String>,
    /// `PAM_RHOST`: remote host, e.g. the client IP for sshd.
    pub rhost: Option<String>,
    /// `PAM_TTY`
    pub tty: Option<String>,
    /// Unix seconds, stamped by the hook since forwarding may be delayed.
    pub occurred_at: i64,
}

/// Stored event, returned by `GET /agents/{id}/auth-events`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEventRecord {
    pub id: i64,
    pub kind: String,
    pub service: String,
    pub user: String,
    pub ruser: Option<String>,
    pub rhost: Option<String>,
    pub tty: Option<String>,
    pub occurred_at: String,
}

/// Which of an agent's PAM events the server pushes to every registered
/// device (they're stored either way). Returned by
/// `GET /agents/pam-notifications` (every agent) and
/// `GET/PUT /agents/{id}/pam-notifications`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PamNotifications {
    pub agent_id: i64,
    pub hostname: String,
    /// Empty: none are pushed (the default for every agent).
    pub kinds: Vec<AuthEventKind>,
}

/// Sent to `PUT /agents/{id}/pam-notifications`: replaces the agent's
/// pushed kinds. Empty turns PAM pushes off for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetPamNotifications {
    pub kinds: Vec<AuthEventKind>,
}
