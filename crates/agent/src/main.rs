mod collectors;
mod config;
mod host;
mod transport;

use std::thread;

use tracing::{error, info};

fn main() {
    let loaded = pulse_config::load::<config::Config>("agent").unwrap_or_else(|err| {
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
