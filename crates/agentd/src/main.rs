mod collectors;
mod config;
mod identity;
mod pam_hook;
mod tasks;

use config::AgentConfig;
use std::time::Duration;

use tasks::{auth_events_loop, pairing_loop, send_metrics_periodically};
use tokio::sync::watch;

#[tokio::main]
async fn main() {
    match std::env::args().nth(1).as_deref() {
        // Invoked by pam_exec, not as the daemon: report one event and exit.
        Some("pam-hook") => {
            pam_hook::run();
            return;
        }
        // For the admin to compare with `pulse-server-cli agents list`
        // before approving.
        Some("fingerprint") => {
            match identity::load_or_create() {
                Ok(identity) => println!("{}", identity.fingerprint),
                Err(err) => {
                    eprintln!("pulse-agentd: {err}");
                    std::process::exit(1);
                }
            }
            return;
        }
        Some("reset-identity") => {
            match identity::reset() {
                Ok(identity) => {
                    println!("new fingerprint: {}", identity.fingerprint);
                    println!(
                        "restart the agent (sudo systemctl restart pulse-agentd); it pairs as a new \
                         request, which the server accepts while pairing is open"
                    );
                }
                Err(err) => {
                    eprintln!("pulse-agentd: {err}");
                    std::process::exit(1);
                }
            }
            return;
        }
        Some(other) => {
            eprintln!(
                "pulse-agentd: unknown command {other:?} (expected none, `fingerprint`, `reset-identity` or `pam-hook`)"
            );
            std::process::exit(1);
        }
        None => {}
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

    let identity = match identity::load_or_create() {
        Ok(identity) => identity,
        Err(err) => {
            // Without a persisted identity every restart would pair as a
            // new agent, so don't run without one.
            tracing::error!("pulse-agentd: {err}");
            std::process::exit(1);
        }
    };
    tracing::info!(fingerprint = %identity.fingerprint, "agent identity loaded");

    let client = http_client(&cfg).unwrap_or_else(|err| {
        tracing::error!("pulse-agentd: {err}");
        std::process::exit(1);
    });

    let pair_url = format!("https://{}/agents/pair", cfg.server_addr);
    let auth_events_url = format!("https://{}/agents/me/auth-events", cfg.server_addr);
    let metrics_url = format!("https://{}/agents/me/metrics", cfg.server_addr);

    // Tasks that call authenticated endpoints read the current token from
    // here; pairing_loop keeps it up to date.
    let (token_tx, token_rx) = watch::channel(None);

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
    // Runs for the agent's whole lifetime, whether or not a token is
    // already stored — see tasks::pairing_loop for why.
    let pairing = tokio::spawn(pairing_loop(client, pair_url, identity, token_tx));

    let _ = tokio::join!(auth_events, metrics, pairing);
}

/// HTTPS client that always verifies the server's cert: against the
/// built-in public CA roots, plus `ca_cert` if set (for a self-signed
/// server cert). Without verification, anyone on the network path could
/// impersonate the server and collect the fingerprint and token.
fn http_client(cfg: &AgentConfig) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder();
    if let Some(path) = &cfg.ca_cert {
        let pem =
            std::fs::read(path).map_err(|e| format!("reading ca_cert {}: {e}", path.display()))?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .map_err(|e| format!("parsing ca_cert {}: {e}", path.display()))?;
        builder = builder.add_root_certificate(cert);
    }
    builder
        .build()
        .map_err(|e| format!("building HTTP client: {e}"))
}
