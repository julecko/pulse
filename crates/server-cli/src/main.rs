//! Admin CLI for the Pulse server: list/approve/revoke/remove agents and
//! view their PAM events and metrics (as a logged-in user), check health,
//! and manage user accounts (directly in the server's database).

mod cli;
mod commands;
mod prompt;
mod session;

use clap::Parser;
use cli::{AgentsCommand, Cli, Command, UsersCommand};
use reqwest::header::HeaderMap;
use session::Session;

#[tokio::main]
async fn main() {
    // See crates/serverd/src/main.rs for why this is needed: the shared
    // workspace Cargo.lock pulls in two rustls crypto backends, so pin one
    // explicitly before any TLS work happens.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install default rustls crypto provider");

    let cli = Cli::parse();

    let base = format!("https://{}", cli.server);

    let result = match cli.command {
        Command::Health => {
            commands::health::check(&session::http_client(HeaderMap::new()), &base).await
        }
        Command::Agents { command } => match Session::login(&base, cli.user).await {
            Ok(session) => {
                let result = run_agents(session.client(), &base, command).await;
                session.logout().await;
                result
            }
            Err(err) => Err(err),
        },
        Command::Users { db, command } => match commands::users::open(db).await {
            Ok(pool) => match command {
                UsersCommand::Add { username } => commands::users::add(&pool, &username).await,
                UsersCommand::Remove { username } => {
                    commands::users::remove(&pool, &username).await
                }
                UsersCommand::List => commands::users::list(&pool).await,
            },
            Err(err) => Err(err),
        },
    };

    if let Err(err) = result {
        eprintln!("pulse-server-cli: {err}");
        std::process::exit(1);
    }
}

async fn run_agents(
    client: &reqwest::Client,
    base: &str,
    command: AgentsCommand,
) -> Result<(), String> {
    match command {
        AgentsCommand::List => commands::agents::list(client, base).await,
        AgentsCommand::Approve { id } => commands::agents::approve(client, base, id).await,
        AgentsCommand::Revoke { id } => commands::agents::revoke(client, base, id).await,
        AgentsCommand::Remove { id } => commands::agents::remove(client, base, id).await,
        AgentsCommand::Events { id } => commands::agents::events(client, base, id).await,
        AgentsCommand::Metrics { id, limit } => {
            commands::agents::metrics(client, base, id, limit).await
        }
    }
}
