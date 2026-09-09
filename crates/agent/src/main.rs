mod collectors;

use pulse_shared::LogConfig;

fn main() {
    let _log_guard = match pulse_shared::init("agent", &LogConfig::default()) {
        Ok(guard) => guard,
        Err(err) => {
            eprintln!("agent: failed to initialise logging: {err}");
            std::process::exit(1);
        }
    };

    tracing::info!("agent starting");

    let metrics = collectors::collect();
    tracing::info!(?metrics, "collected metrics");
}
