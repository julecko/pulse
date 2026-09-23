mod collectors;
mod config;
mod identity;

use std::time::Duration;

use config::AgentConfig;
use identity::Identity;
use protocol::{PairRequest, PairResponse};

const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const METRICS_PRINT_INTERVAL: Duration = Duration::from_secs(20);
const PAIRING_POLL_INTERVAL: Duration = Duration::from_secs(15);

#[tokio::main]
async fn main() {
    // See crates/server/src/main.rs for why this is needed: the shared
    // workspace Cargo.lock pulls in two rustls crypto backends, so pin one
    // explicitly before any TLS work happens.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install default rustls crypto provider");

    let cfg: AgentConfig = pulse_shared::config::load("agent").unwrap_or_else(|err| {
        eprintln!("agent: failed to load config: {err}");
        std::process::exit(1);
    });

    let _log_guard = match pulse_shared::init("agent", &cfg.log) {
        Ok(guard) => guard,
        Err(err) => {
            eprintln!("agent: failed to initialise logging: {err}");
            std::process::exit(1);
        }
    };

    tracing::info!(
        server_addr = %cfg.server_addr,
        interval_secs = cfg.interval_secs,
        "agent starting"
    );

    let identity = identity::load_or_create();
    tracing::info!(
        fingerprint = %identity.fingerprint,
        paired = identity.token.is_some(),
        "agent identity loaded"
    );

    // Server uses a self-signed cert in dev and there's no CA trust
    // distribution yet, so skip verification for now.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("failed to build HTTP client");

    let health_url = format!("https://{}/healthz", cfg.server_addr);

    let health_check = tokio::spawn(check_health_periodically(client.clone(), health_url));
    //let metrics_print = tokio::spawn(print_metrics_periodically());

    let mut tasks = vec![health_check /*, metrics_print*/];

    if identity.token.is_none() {
        let pair_url = format!("https://{}/agents/pair", cfg.server_addr);
        tasks.push(tokio::spawn(pairing_loop(client, pair_url, identity)));
    }

    for task in tasks {
        let _ = task.await;
    }
}

async fn check_health_periodically(client: reqwest::Client, url: String) {
    let mut ticker = tokio::time::interval(HEALTH_CHECK_INTERVAL);
    loop {
        ticker.tick().await;
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(status = %resp.status(), "server healthy");
            }
            Ok(resp) => {
                tracing::warn!(status = %resp.status(), "server responded with error status");
            }
            Err(err) => {
                tracing::warn!(%err, "health check failed");
            }
        }
    }
}

/*async fn print_metrics_periodically() {
    let mut ticker = tokio::time::interval(METRICS_PRINT_INTERVAL);
    loop {
        ticker.tick().await;
        let metrics = collectors::collect();
        tracing::info!(?metrics, "collected metrics");
    }
}*/

/// Polls `/agents/pair` until the server reports this fingerprint as
/// approved, then persists the issued token and returns. Runs independently
/// of the health-check/metrics loops, neither of which needs a token today.
async fn pairing_loop(client: reqwest::Client, url: String, mut identity: Identity) {
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
                tracing::info!("agent approved, pairing complete");
                identity.token = Some(token);
                identity::save(&identity);
                return;
            }
            Ok(PairResponse::Pending) => {
                tracing::debug!("pairing still pending approval");
            }
            Ok(PairResponse::Revoked) => {
                tracing::warn!("pairing request was revoked");
            }
            Err(err) => {
                tracing::warn!(%err, %status, "failed to parse pairing response");
            }
        }
    }
}
