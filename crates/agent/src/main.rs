mod collectors;
mod config;
mod host;
mod transport;

use std::thread;

fn main() {
    let loaded = pulse_config::load::<config::Config>("agent").unwrap_or_else(|err| {
        eprintln!("{err}");
        std::process::exit(1);
    });
    if loaded.found {
        println!("config: loaded {}", loaded.path.display());
    } else {
        println!("config: none at {}, using defaults", loaded.path.display());
    }
    let cfg = loaded.config;
    println!(
        "pulse agent: reporting to {} every {}s",
        cfg.server, cfg.interval_secs
    );

    loop {
        let report = collectors::collect();
        match transport::send(&cfg.server, &report) {
            Ok(()) => println!(
                "sent report: {} metric section(s), host {}",
                report.metrics.section_count(),
                report.host.hostname,
            ),
            Err(err) => eprintln!("failed to send report to {}: {err}", cfg.server),
        }
        thread::sleep(cfg.interval());
    }
}
