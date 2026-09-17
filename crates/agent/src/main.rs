mod collectors;
mod config;

use config::AgentConfig;

fn main() {
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

    let metrics = collectors::collect();
    tracing::info!(?metrics, "collected metrics");
}
