mod collectors;
mod config;

use std::time::Duration;

use config::AgentConfig;

const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const METRICS_PRINT_INTERVAL: Duration = Duration::from_secs(20);

#[tokio::main]
async fn main() {
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

    // Server uses a self-signed cert in dev and there's no CA trust
    // distribution yet, so skip verification for now.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("failed to build HTTP client");

    let health_url = format!("https://{}/healthz", cfg.server_addr);

    let health_check = tokio::spawn(check_health_periodically(client, health_url));
    let metrics_print = tokio::spawn(print_metrics_periodically());

    let _ = tokio::join!(health_check, metrics_print);
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

async fn print_metrics_periodically() {
    let mut ticker = tokio::time::interval(METRICS_PRINT_INTERVAL);
    loop {
        ticker.tick().await;
        let metrics = collectors::collect();
        tracing::info!(?metrics, "collected metrics");
    }
}
