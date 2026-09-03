mod collectors;
mod host;
mod transport;

use std::thread;
use std::time::Duration;

/// Where to ship reports. Override with `PULSE_SERVER=host:port`.
const DEFAULT_SERVER: &str = "127.0.0.1:9000";
/// Delay between samples.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(5);

fn main() {
    let server = std::env::var("PULSE_SERVER").unwrap_or_else(|_| DEFAULT_SERVER.to_string());

    loop {
        let report = collectors::collect();
        match transport::send(&server, &report) {
            Ok(()) => println!(
                "sent report: {} metric section(s), host {}",
                report.metrics.section_count(),
                report.host.hostname,
            ),
            Err(err) => eprintln!("failed to send report to {server}: {err}"),
        }
        thread::sleep(SAMPLE_INTERVAL);
    }
}
