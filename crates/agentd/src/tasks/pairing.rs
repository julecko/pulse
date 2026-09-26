use std::time::Duration;

use protocol::{PairRequest, PairResponse};
use reqwest::StatusCode;
use tokio::sync::watch;

use crate::identity::{self, Identity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Pending,
    Approved,
    Revoked,
}

const PAIRING_POLL_INTERVAL: Duration = Duration::from_secs(60);
/// Wait after the server refuses a new pairing request (pairing closed, or
/// too many pending), instead of asking again every interval.
const PAIRING_REFUSED_BACKOFF: Duration = Duration::from_secs(5 * 60);
/// Longest `Retry-After` honored when rate-limited.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(15 * 60);

/// Polls `/agents/pair` every minute for as long as the agent runs (backing
/// off when the server refuses or rate-limits it), proving ownership of the
/// fingerprint with the agent's secret each time. The server never sends a
/// credential back; it just reports the status, and once that's `approved`
/// the secret itself is the bearer token. Every poll re-confirms the
/// status, since an approved agent can be revoked or removed at any time.
///
/// The bearer token for the approval-gated tasks (metrics, auth events) is
/// published on `token_tx`: the secret while approved, `None` otherwise.
pub async fn pairing_loop(
    client: reqwest::Client,
    url: String,
    identity: Identity,
    token_tx: watch::Sender<Option<String>>,
) {
    let mut last_status = None;
    let mut delay = Duration::ZERO;
    loop {
        tokio::time::sleep(delay).await;
        delay = PAIRING_POLL_INTERVAL;

        let host = identity::host_info();
        let req = PairRequest {
            fingerprint: identity.fingerprint.clone(),
            secret: identity.secret.clone(),
            hostname: host.hostname,
            os_name: host.os_name,
            os_version: host.os_version,
            kernel_version: host.kernel_version,
            arch: host.arch,
        };

        let response = match client.post(&url).json(&req).send().await {
            Ok(resp) => resp,
            Err(err) => {
                // The cause (e.g. a rejected server cert) is only in the
                // source chain, not in reqwest's own message.
                tracing::warn!(err = %error_chain(&err), "pairing request failed");
                continue;
            }
        };

        let status = response.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
                .map(Duration::from_secs)
                .unwrap_or(PAIRING_REFUSED_BACKOFF);
            delay = retry_after.clamp(PAIRING_POLL_INTERVAL, MAX_RETRY_AFTER);
            tracing::warn!(
                retry_in_secs = delay.as_secs(),
                "pairing rate-limited by the server"
            );
            continue;
        }
        if matches!(
            status,
            StatusCode::FORBIDDEN | StatusCode::CONFLICT | StatusCode::SERVICE_UNAVAILABLE
        ) {
            // Pairing closed, a registration race, or too many pending
            // requests; the body says which. None fixes itself quickly.
            let body = response.text().await.unwrap_or_default();
            delay = PAIRING_REFUSED_BACKOFF;
            tracing::warn!(%status, body, retry_in_secs = delay.as_secs(), "server isn't accepting this agent's pairing request");
            continue;
        }
        if !status.is_success() {
            // Most likely cause: the server is running an older build that
            // disagrees with this agent's PairRequest/PairResponse shape.
            let body = response.text().await.unwrap_or_default();
            tracing::warn!(%status, body, "server rejected pairing request");
            continue;
        }

        let status = match response.json::<PairResponse>().await {
            Ok(PairResponse::Approved) => Status::Approved,
            Ok(PairResponse::Pending) => Status::Pending,
            Ok(PairResponse::Revoked) => Status::Revoked,
            Err(err) => {
                tracing::warn!(%err, %status, "failed to parse pairing response");
                continue;
            }
        };

        // Log only changes; this runs every minute.
        if last_status != Some(status) {
            match status {
                Status::Approved => tracing::info!("agent approved"),
                Status::Pending => tracing::info!(
                    fingerprint = %identity.fingerprint,
                    "waiting for approval on the server"
                ),
                Status::Revoked => tracing::warn!(
                    "agent access revoked; to pair again: `agents remove <id>` on the server, \
                     then `pulse-agentd reset-identity` here and restart"
                ),
            }
            last_status = Some(status);
        }

        let token = (status == Status::Approved).then(|| identity.secret.clone());
        token_tx.send_if_modified(|current| {
            if *current == token {
                return false;
            }
            *current = token;
            true
        });
    }
}

fn error_chain(err: &dyn std::error::Error) -> String {
    let mut msg = err.to_string();
    let mut source = err.source();
    while let Some(err) = source {
        msg.push_str(": ");
        msg.push_str(&err.to_string());
        source = err.source();
    }
    msg
}
