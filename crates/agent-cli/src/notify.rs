//! `pulse-agent-cli notify`: sends a plain push notification to every
//! device registered with the server (the mobile app), through the running
//! agent, which holds the token. The agent's socket only takes messages from
//! root or the agent's own user, so this runs via sudo.
//!
//! Waits for the agent's one-line reply (see [`protocol::LocalMessage`]),
//! so failures (agent not approved, push not configured on the server, rate
//! limited, ...) are reported rather than lost.

use std::io::{ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use protocol::{LocalMessage, Notification};

use crate::pam_hook;

const WRITE_TIMEOUT: Duration = Duration::from_secs(2);
/// Longer than the agent's own 30s request timeout, so its reply (an error,
/// if the server doesn't answer) arrives first.
const REPLY_TIMEOUT: Duration = Duration::from_secs(40);
const MAX_REPLY_BYTES: u64 = 4 * 1024;

/// `Ok` with what the server said (how many devices it's going to).
pub fn run(title: Option<String>, message: String) -> Result<String, String> {
    let notification = Notification { title, message };
    notification.validate()?;

    let config = pulse_shared::config::default_path("agent");
    let socket = pam_hook::socket_path(&config).map_err(|e| e.to_string())?;

    let mut stream = UnixStream::connect(&socket).map_err(|e| connect_error(&socket, e))?;
    stream
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .and_then(|()| stream.set_read_timeout(Some(REPLY_TIMEOUT)))
        .map_err(|e| e.to_string())?;

    let message = LocalMessage::Notify {
        notify: notification,
    };
    serde_json::to_writer(&mut stream, &message)
        .map_err(|e| format!("sending to the agent: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("sending to the agent: {e}"))?;
    // The agent reads until EOF, then replies.
    stream
        .shutdown(Shutdown::Write)
        .map_err(|e| format!("sending to the agent: {e}"))?;

    let mut reply = String::new();
    stream
        .take(MAX_REPLY_BYTES)
        .read_to_string(&mut reply)
        .map_err(|e| match e.kind() {
            ErrorKind::WouldBlock | ErrorKind::TimedOut => {
                "the agent didn't reply in time; the notification may or may not have been sent"
                    .to_string()
            }
            _ => format!("reading the agent's reply: {e}"),
        })?;

    let reply = protocol::escape_for_display(reply.trim_end()).into_owned();
    if reply == "ok" {
        Ok(String::new())
    } else if let Some(details) = reply.strip_prefix("ok ") {
        Ok(details.to_string())
    } else if let Some(err) = reply.strip_prefix("error ") {
        Err(err.to_string())
    } else if reply.is_empty() {
        Err(
            "the agent closed the connection without replying; if it was just upgraded, \
             restart it: sudo systemctl restart pulse-agentd"
                .to_string(),
        )
    } else {
        Err(format!("unexpected reply from the agent: {reply}"))
    }
}

fn connect_error(socket: &Path, err: std::io::Error) -> String {
    match err.kind() {
        ErrorKind::PermissionDenied => format!(
            "permission denied on {}; run it as root (sudo pulse-agent-cli notify ...)",
            socket.display()
        ),
        _ => format!(
            "can't reach pulse-agentd at {}: {err}; is it running? (sudo systemctl status pulse-agentd)",
            socket.display()
        ),
    }
}
