use std::process::ExitCode;

fn main() -> ExitCode {
    pulse_cli::run::<pulse_server::Config>(pulse_cli::App {
        name: "server",
        unit: "pulse-server",
        daemon: "/usr/lib/pulse/pulse-serverd",
    })
}
