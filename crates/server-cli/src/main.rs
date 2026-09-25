//! Admin CLI for the Pulse server: list/approve/revoke/remove agents, view
//! their PAM events, check health.

mod cli;
mod commands;

use clap::Parser;
use cli::{AgentsCommand, Cli, Command};

#[tokio::main]
async fn main() {
    // See crates/server/src/main.rs for why this is needed: the shared
    // workspace Cargo.lock pulls in two rustls crypto backends, so pin one
    // explicitly before any TLS work happens.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install default rustls crypto provider");

    let cli = Cli::parse();

    // Talks to the server's self-signed dev cert; there's no CA trust
    // distribution yet, same as the agent binary.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("failed to build HTTP client");

    let base = format!("https://{}", cli.server);

    let result = match cli.command {
        Command::Health => commands::health::check(&client, &base).await,
        Command::Agents { command } => match command {
            AgentsCommand::List => commands::agents::list(&client, &base).await,
            AgentsCommand::Approve { id } => commands::agents::approve(&client, &base, id).await,
            AgentsCommand::Revoke { id } => commands::agents::revoke(&client, &base, id).await,
            AgentsCommand::Remove { id } => commands::agents::remove(&client, &base, id).await,
            AgentsCommand::Events { id } => commands::agents::events(&client, &base, id).await,
        },
    };

    if let Err(err) = result {
        eprintln!("server-cli: {err}");
        std::process::exit(1);
    }
}
