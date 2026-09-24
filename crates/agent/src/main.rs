mod collectors;
mod config;
mod identity;
mod tasks;

use config::AgentConfig;
use tasks::{check_health_periodically, pairing_loop};

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
    let pair_url = format!("https://{}/agents/pair", cfg.server_addr);

    // Runs for the agent's whole lifetime, whether or not a token is
    // already stored — see tasks::pairing_loop for why.
    let health_check = tokio::spawn(check_health_periodically(client.clone(), health_url));
    let pairing = tokio::spawn(pairing_loop(client, pair_url, identity));

    let _ = tokio::join!(health_check, pairing);
}
