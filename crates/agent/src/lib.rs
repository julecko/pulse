//! pulse-agentd internals. The `pulse-agentd` binary is a thin `main` over
//! [`run`]; the `pulse-agent` binary is the (future) config/control front-end.

mod collectors;
mod config;
mod host;
mod transport;

pub use config::Config;

use std::thread;

use tracing::{error, info};

/// Run the agent: load config, set up logging, then sample and ship forever.
pub fn run() {
    let loaded = pulse_config::load::<Config>("agent").unwrap_or_else(|err| {
        eprintln!("{err}");
        std::process::exit(1);
    });
    let cfg = loaded.config;

    let _log_guard = pulse_config::log::init("agent", &cfg.log).unwrap_or_else(|err| {
        eprintln!("logging setup failed: {err}");
        std::process::exit(1);
    });

    if loaded.found {
        info!(path = %loaded.path.display(), "loaded config");
    } else {
        info!(path = %loaded.path.display(), "no config file, using defaults");
    }
    info!(
        server = %cfg.server,
        interval_secs = cfg.interval_secs,
        "pulse agent starting"
    );

    loop {
        let report = collectors::collect();
        match transport::send(&cfg.server, &report) {
            Ok(()) => info!(
                sections = report.metrics.section_count(),
                host = %report.host.hostname,
                "report sent"
            ),
            Err(err) => error!(server = %cfg.server, %err, "failed to send report"),
        }
        thread::sleep(cfg.interval());
    }
}
