use serde::{Deserialize, Serialize};

use crate::AuthEvent;

/// Longest notification title, in characters.
pub const MAX_NOTIFICATION_TITLE_LEN: usize = 100;
/// Longest notification message, in characters.
pub const MAX_NOTIFICATION_MESSAGE_LEN: usize = 1000;

/// A plain push notification sent by `pulse-agent-cli notify`, forwarded by
/// the agent to `POST /agents/me/notify`. The server pushes it to every
/// registered device and doesn't store it. The owning agent is taken from
/// the bearer token, and its hostname is always shown with the title, so an
/// agent can't pass its notifications off as another host's.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    /// Unset: the notification is titled with the agent's hostname alone.
    pub title: Option<String>,
    pub message: String,
}

impl Notification {
    /// Checked by both `pulse-agent-cli` (to fail early) and the server.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(title) = &self.title {
            if title.trim().is_empty() || title.chars().count() > MAX_NOTIFICATION_TITLE_LEN {
                return Err(format!(
                    "title must be 1-{MAX_NOTIFICATION_TITLE_LEN} characters"
                ));
            }
            if title.chars().any(crate::is_unsafe_display_char) {
                return Err("title must not contain control characters".to_string());
            }
        }
        if self.message.trim().is_empty()
            || self.message.chars().count() > MAX_NOTIFICATION_MESSAGE_LEN
        {
            return Err(format!(
                "message must be 1-{MAX_NOTIFICATION_MESSAGE_LEN} characters"
            ));
        }
        // Line breaks are fine in a notification body; nothing else is.
        if self
            .message
            .chars()
            .any(|c| c != '\n' && crate::is_unsafe_display_char(c))
        {
            return Err(
                "message must not contain control characters (other than line breaks)".to_string(),
            );
        }
        Ok(())
    }
}

/// One message on the agent's local Unix socket. PAM events are sent bare
/// (as they were before notifications existed), notifications wrapped as
/// `{"notify": {...}}`. The agent replies to a notification with one line,
/// `ok <details>` or `error <reason>`; PAM events get no reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LocalMessage {
    Notify { notify: Notification },
    AuthEvent(AuthEvent),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(title: Option<&str>, message: &str) -> Notification {
        Notification {
            title: title.map(str::to_string),
            message: message.to_string(),
        }
    }

    #[test]
    fn validates() {
        assert!(note(None, "backup done").validate().is_ok());
        assert!(note(Some("Backup"), "done\n3 GiB").validate().is_ok());
        assert!(note(None, " ").validate().is_err());
        assert!(note(Some(""), "x").validate().is_err());
        assert!(note(Some("a\nb"), "x").validate().is_err());
        assert!(note(None, "x\x1b[2J").validate().is_err());
        assert!(
            note(None, &"x".repeat(MAX_NOTIFICATION_MESSAGE_LEN + 1))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn local_messages_are_told_apart() {
        let notify = r#"{"notify":{"title":null,"message":"hi"}}"#;
        assert!(matches!(
            serde_json::from_str::<LocalMessage>(notify).unwrap(),
            LocalMessage::Notify { .. }
        ));
        let event = r#"{"kind":"auth_failure","service":"sshd","user":"root",
            "ruser":null,"rhost":"192.0.2.1","tty":null,"occurred_at":0}"#;
        assert!(matches!(
            serde_json::from_str::<LocalMessage>(event).unwrap(),
            LocalMessage::AuthEvent(_)
        ));
    }
}
