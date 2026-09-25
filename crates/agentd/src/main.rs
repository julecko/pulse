mod collectors;
mod config;
mod identity;
mod pam_hook;
mod tasks;

use config::AgentConfig;
use std::time::Duration;

use tasks::{auth_events_loop, check_health_periodically, pairing_loop, send_metrics_periodically};
use tokio::sync::watch;

#[tokio::main]
async fn main() {
    // Invoked by pam_exec, not as the daemon: report one event and exit.
    if std::env::args().nth(1).as_deref() == Some("pam-hook") {
        pam_hook::run();
        return;
    }

    // See crates/serverd/src/main.rs for why this is needed: the shared
    // workspace Cargo.lock pulls in two rustls crypto backends, so pin one
    // explicitly before any TLS work happens.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install default rustls crypto provider");

    let cfg: AgentConfig = pulse_shared::config::load("agent").unwrap_or_else(|err| {
        eprintln!("pulse-agentd: failed to load config: {err}");
        std::process::exit(1);
    });

    // A zero period would panic inside tokio's interval timer.
    if cfg.interval_secs == 0 {
        eprintln!("pulse-agentd: interval_secs must be at least 1");
        std::process::exit(1);
    }

    let _log_guard = match pulse_shared::init("agent", &cfg.log) {
        Ok(guard) => guard,
        Err(err) => {
            eprintln!("pulse-agentd: failed to initialise logging: {err}");
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
    let pair_url = format!("https://{}/agents/pair", cfg.server_addr);
    let auth_events_url = format!("https://{}/agents/me/auth-events", cfg.server_addr);
    let metrics_url = format!("https://{}/agents/me/metrics", cfg.server_addr);

    // Tasks that call authenticated endpoints read the current token from
    // here; pairing_loop keeps it up to date.
    let (token_tx, token_rx) = watch::channel(identity.token.clone());

    // Runs for the agent's whole lifetime, whether or not a token is
    // already stored — see tasks::pairing_loop for why.
    let health_check = tokio::spawn(check_health_periodically(client.clone(), health_url));
    let auth_events = tokio::spawn(auth_events_loop(
        client.clone(),
        auth_events_url,
        cfg.pam_socket_path(),
        token_rx.clone(),
    ));
    let metrics = tokio::spawn(send_metrics_periodically(
        client.clone(),
        metrics_url,
        Duration::from_secs(cfg.interval_secs),
        token_rx,
    ));
    let pairing = tokio::spawn(pairing_loop(client, pair_url, identity, token_tx));

    let _ = tokio::join!(health_check, auth_events, metrics, pairing);
}
