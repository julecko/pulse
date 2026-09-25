use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthEventKind {
    SessionOpen,
    SessionClose,
    AuthFailure,
}

impl AuthEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SessionOpen => "session_open",
            Self::SessionClose => "session_close",
            Self::AuthFailure => "auth_failure",
        }
    }
}

/// A PAM event captured on the agent's host by `pulse-agentd pam-hook`, forwarded
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
