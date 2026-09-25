//! Receives PAM events from `agent pam-hook` over a local Unix socket and
//! forwards each one to the server, authenticated with the agent's token.
//!
//! The socket itself needs no auth: the kernel tells us the peer's uid, and
//! only root (which pam_exec runs as for sshd/sudo/su) or the agent's own
//! user may report events — otherwise any local user could forge logins.
//!
//! Nothing is kept on the agent: each event is sent on its own as soon as
//! it arrives, and dropped if there's no token (pending/revoked) or the
//! send fails.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::time::Duration;

use protocol::AuthEvent;
use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

const MAX_MESSAGE_BYTES: u64 = 8 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(1);

pub async fn auth_events_loop(
    client: reqwest::Client,
    url: String,
    socket_path: PathBuf,
    token: watch::Receiver<Option<String>>,
) {
    let listener = match bind(&socket_path) {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(%err, path = %socket_path.display(), "failed to bind PAM event socket; auth events disabled");
            return;
        }
    };
    tracing::info!(path = %socket_path.display(), "listening for PAM events");

    // The socket file is created by us, so its owner is the agent's own uid.
    let own_uid = std::fs::metadata(&socket_path).map(|m| m.uid()).ok();

    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(err) => {
                tracing::warn!(%err, "failed to accept PAM event connection");
                continue;
            }
        };

        let uid = match stream.peer_cred() {
            Ok(cred) => cred.uid(),
            Err(err) => {
                tracing::warn!(%err, "failed to read PAM event peer credentials");
                continue;
            }
        };
        if uid != 0 && Some(uid) != own_uid {
            tracing::warn!(uid, "rejected PAM event from unprivileged user");
            continue;
        }

        let client = client.clone();
        let url = url.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let event = match read_event(stream).await {
                Ok(event) => event,
                Err(err) => {
                    tracing::warn!(%err, "invalid PAM event");
                    return;
                }
            };
            tracing::debug!(?event, "received PAM event");

            let Some(token) = token.borrow().clone() else {
                tracing::debug!("not paired; dropping PAM event");
                return;
            };
            forward(&client, &url, &token, &event).await;
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

async fn read_event(stream: UnixStream) -> Result<AuthEvent, String> {
    let mut buf = Vec::new();
    tokio::time::timeout(
        READ_TIMEOUT,
        stream.take(MAX_MESSAGE_BYTES).read_to_end(&mut buf),
    )
    .await
    .map_err(|_| "timed out reading event".to_string())?
    .map_err(|e| e.to_string())?;

    serde_json::from_slice(&buf).map_err(|e| e.to_string())
}

/// Sends one event; on any failure it's logged and dropped.
async fn forward(client: &reqwest::Client, url: &str, token: &str, event: &AuthEvent) {
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
