//! CLI for the Pulse agent host: show or reset the agent's identity, and
//! the PAM hook `pam_exec` calls on every login. Everything that isn't the
//! long-running daemon (`pulse-agentd`) lives here.

mod pam_hook;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "pulse-agent-cli", about = "CLI for the Pulse monitoring agent")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print this agent's fingerprint, to compare with `pulse-server-cli
    /// agents list` before approving it (creates the identity if there's
    /// none yet)
    Fingerprint,
    /// Replace the agent's identity with a new one; it then pairs as a new
    /// request (after a revoke, or if its secret may have leaked)
    ResetIdentity,
    /// Report one PAM event to the running agent. Called by pam_exec, not
    /// by hand; always silent and exits 0
    #[command(hide = true)]
    PamHook,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::PamHook => pam_hook::run(),
        Command::Fingerprint => match pulse_shared::agent::load_or_create() {
            Ok(identity) => println!("{}", identity.fingerprint),
            Err(err) => fail(&err),
        },
        Command::ResetIdentity => match pulse_shared::agent::reset() {
            Ok(identity) => {
                println!("new fingerprint: {}", identity.fingerprint);
                println!(
                    "restart the agent (sudo systemctl restart pulse-agentd); it pairs as a new \
                     request, which the server accepts while pairing is open"
                );
            }
            Err(err) => fail(&err),
        },
    }
}

fn fail(err: &str) -> ! {
    eprintln!("pulse-agent-cli: {err}");
    std::process::exit(1);
}
