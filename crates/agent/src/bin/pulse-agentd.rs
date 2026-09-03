//! pulse-agentd — the pulse metrics agent daemon.
//!
//! Not meant to be run by hand; it is started via systemd
//! (`systemctl start pulse-agent`) or the `pulse-agent` front-end.

fn main() {
    pulse_agent::run();
}
