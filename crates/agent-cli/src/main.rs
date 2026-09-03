use std::process::ExitCode;

fn main() -> ExitCode {
    pulse_cli::run::<pulse_agent::Config>(pulse_cli::App {
        name: "agent",
        unit: "pulse-agent",
        daemon: "/usr/lib/pulse/pulse-agentd",
    })
}
