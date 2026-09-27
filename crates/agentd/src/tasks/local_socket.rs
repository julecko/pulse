//! The agent's local Unix socket, for the one-shot `pulse-agent-cli`
//! commands that need the agent's token (see [`protocol::LocalMessage`]):
//! - PAM events from `pulse-agent-cli pam-hook`, forwarded to the server
//!   without a reply (the hook has already exited)
//! - plain notifications from `pulse-agent-cli notify`, forwarded to the
//!   server, which pushes them to every registered device; the sender gets
//!   a one-line reply saying whether that worked
//!
//! The socket itself needs no auth: the kernel tells us the peer's uid, and
//! only root (which pam_exec runs as for sshd/sudo/su) or the agent's own
//! user may send anything — otherwise any local user could forge logins or
//! push to everyone's phone.
//!
//! Nothing is kept on the agent: each message is sent on its own as soon as
//! it arrives, and dropped if there's no token (pending/revoked) or the
//! send fails.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::time::Duration;

use protocol::{AuthEvent, LocalMessage, Notification};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

const MAX_MESSAGE_BYTES: u64 = 8 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(1);
/// Longest we wait for `pulse-agent-cli notify` to take its reply.
const REPLY_TIMEOUT: Duration = Duration::from_secs(1);
/// Longest server error body passed on to `pulse-agent-cli notify`.
const MAX_REPLY_CHARS: usize = 300;

pub async fn local_socket_loop(
    client: reqwest::Client,
    auth_events_url: String,
    notify_url: String,
    socket_path: PathBuf,
    token: watch::Receiver<Option<String>>,
) {
    let listener = match bind(&socket_path) {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(%err, path = %socket_path.display(), "failed to bind local socket; auth events and notifications disabled");
            return;
        }
    };
    tracing::info!(path = %socket_path.display(), "listening for PAM events and notifications");

    // The socket file is created by us, so its owner is the agent's own uid.
    let own_uid = std::fs::metadata(&socket_path).map(|m| m.uid()).ok();

    loop {
        let mut stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(err) => {
                tracing::warn!(%err, "failed to accept local socket connection");
                continue;
            }
        };

        let uid = match stream.peer_cred() {
            Ok(cred) => cred.uid(),
            Err(err) => {
                tracing::warn!(%err, "failed to read local socket peer credentials");
                continue;
            }
        };
        if uid != 0 && Some(uid) != own_uid {
            tracing::warn!(uid, "rejected local socket message from unprivileged user");
            continue;
        }

        let client = client.clone();
        let auth_events_url = auth_events_url.clone();
        let notify_url = notify_url.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let message = match read_message(&mut stream).await {
                Ok(message) => message,
                Err(err) => {
                    tracing::warn!(%err, "invalid local socket message");
                    return;
                }
            };
            let token = token.borrow().clone();

            match message {
                LocalMessage::AuthEvent(event) => {
                    tracing::debug!(?event, "received PAM event");
                    let Some(token) = token else {
                        tracing::debug!("not paired; dropping PAM event");
                        return;
                    };
                    forward_auth_event(&client, &auth_events_url, &token, &event).await;
                }
                LocalMessage::Notify { notify } => {
                    let result = match token {
                        Some(token) => send_notification(&client, &notify_url, &token, &notify).await,
                        None => Err(
                            "this agent isn't approved by the server, so it can't send notifications"
                                .to_string(),
                        ),
                    };
                    let reply = match result {
                        Ok(details) => format!("ok {details}\n"),
                        Err(err) => {
                            tracing::warn!(%err, "notification not sent");
                            format!("error {err}\n")
                        }
                    };
                    let _ = tokio::time::timeout(REPLY_TIMEOUT, stream.write_all(reply.as_bytes()))
                        .await;
                }
            }
        });
    }
}

fn bind(path: &PathBuf) -> std::io::Result<UnixListener> {
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    // Left over from a previous run; binding fails if the file exists.
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Reads one message: everything up to the sender closing (or shutting
/// down) its end.
async fn read_message(stream: &mut UnixStream) -> Result<LocalMessage, String> {
    let mut buf = Vec::new();
    tokio::time::timeout(
        READ_TIMEOUT,
        stream.take(MAX_MESSAGE_BYTES).read_to_end(&mut buf),
    )
    .await
    .map_err(|_| "timed out reading message".to_string())?
    .map_err(|e| e.to_string())?;

    serde_json::from_slice(&buf).map_err(|e| e.to_string())
}

/// Sends one event; on any failure it's logged and dropped.
async fn forward_auth_event(client: &reqwest::Client, url: &str, token: &str, event: &AuthEvent) {
    match client.post(url).bearer_auth(token).json(event).send().await {
        Ok(resp) if resp.status().is_success() => {
            tracing::debug!("forwarded PAM event");
        }
        Ok(resp) => {
            tracing::warn!(status = %resp.status(), "server rejected PAM event; dropped");
        }
        Err(err) => {
            tracing::warn!(%err, "failed to forward PAM event; dropped");
        }
    }
}

/// Sends one notification; `Ok` with the server's reply (how many devices
/// it goes to), `Err` with why it wasn't sent.
async fn send_notification(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    notification: &Notification,
) -> Result<String, String> {
    let resp = client
        .post(url)
        .bearer_auth(token)
        .json(notification)
        .send()
        .await
        .map_err(|e| format!("couldn't reach the server: {e}"))?;
    let status = resp.status();
    let body: String = resp
        .text()
        .await
        .unwrap_or_default()
        .chars()
        .take(MAX_REPLY_CHARS)
        .collect();
    // The reply is one line.
    let body = body.replace('\n', " ");
    if status.is_success() {
        Ok(body)
    } else if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        Err(format!("too many notifications from this agent: {body}"))
    } else {
        Err(format!("server refused it ({status}): {body}"))
    }
}
