use std::time::Duration;

use protocol::{PairRequest, PairResponse};

use crate::identity::{self, Identity};

const PAIRING_POLL_INTERVAL: Duration = Duration::from_secs(15);

/// Polls `/agents/pair` on an interval for as long as the agent runs,
/// keeping the stored token in sync with the server's view of this
/// fingerprint. A token existing locally is never treated as proof of
/// approval by itself — every tick re-confirms the actual status, since a
/// previously-approved agent can be revoked or removed server-side at any
/// time. Once approval-gated features (e.g. sending metrics) exist, they
/// should check the current state this loop maintains rather than just
/// "is there a token".
pub async fn pairing_loop(client: reqwest::Client, url: String, mut identity: Identity) {
    let mut ticker = tokio::time::interval(PAIRING_POLL_INTERVAL);
    loop {
        ticker.tick().await;

        let host = identity::host_info();
        let req = PairRequest {
            fingerprint: identity.fingerprint.to_string(),
            hostname: host.hostname,
            os_name: host.os_name,
            os_version: host.os_version,
            kernel_version: host.kernel_version,
            arch: host.arch,
        };

        let response = match client.post(&url).json(&req).send().await {
            Ok(resp) => resp,
            Err(err) => {
                tracing::warn!(%err, "pairing request failed");
                continue;
            }
        };

        let status = response.status();
        if !status.is_success() {
            // Most likely cause: the server is running an older build that
            // disagrees with this agent's PairRequest/PairResponse shape.
            let body = response.text().await.unwrap_or_default();
            tracing::warn!(%status, body, "server rejected pairing request");
            continue;
        }

        match response.json::<PairResponse>().await {
            Ok(PairResponse::Approved { token }) => {
                tracing::info!("agent approved");
                if identity.token.as_deref() != Some(token.as_str()) {
                    identity.token = Some(token);
                    identity::save(&identity);
                }
            }
            Ok(PairResponse::Pending) => {
                tracing::debug!("pairing still pending approval");
                if identity.token.take().is_some() {
                    identity::save(&identity);
                }
            }
            Ok(PairResponse::Revoked) => {
                tracing::warn!("agent access revoked");
                if identity.token.take().is_some() {
                    identity::save(&identity);
                }
            }
            Err(err) => {
                tracing::warn!(%err, %status, "failed to parse pairing response");
            }
        }
    }
}
