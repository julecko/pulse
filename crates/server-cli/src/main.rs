//! Admin CLI for the Pulse server: list/approve/revoke agents, check health.

use clap::{Parser, Subcommand};
use protocol::{AgentSummary, ApproveResponse};

#[derive(Parser)]
#[command(name = "server-cli", about = "Admin CLI for the Pulse server")]
struct Cli {
    /// Pulse server address (host:port)
    #[arg(long, global = true, default_value = "127.0.0.1:8443")]
    server: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check server health (GET /healthz)
    Health,
    /// Manage agents
    Agents {
        #[command(subcommand)]
        command: AgentsCommand,
    },
}

#[derive(Subcommand)]
enum AgentsCommand {
    /// List all agents (pending, approved, revoked)
    List,
    /// Approve a pending agent, printing the issued token
    Approve { id: i64 },
    /// Revoke an agent's access
    Revoke { id: i64 },
    /// Delete an agent entirely, so it can pair again as a fresh request
    Remove { id: i64 },
}

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
        Command::Health => health(&client, &base).await,
        Command::Agents { command } => match command {
            AgentsCommand::List => list_agents(&client, &base).await,
            AgentsCommand::Approve { id } => approve(&client, &base, id).await,
            AgentsCommand::Revoke { id } => revoke(&client, &base, id).await,
            AgentsCommand::Remove { id } => remove(&client, &base, id).await,
        },
    };

    if let Err(err) = result {
        eprintln!("server-cli: {err}");
        std::process::exit(1);
    }
}

async fn health(client: &reqwest::Client, base: &str) -> Result<(), String> {
    let resp = client
        .get(format!("{base}/healthz"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    let status = resp.status();
    if status.is_success() {
        println!("ok ({status})");
        Ok(())
    } else {
        Err(format!("server responded with {status}"))
    }
}

async fn list_agents(client: &reqwest::Client, base: &str) -> Result<(), String> {
    let agents: Vec<AgentSummary> = client
        .get(format!("{base}/agents"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("server error: {e}"))?
        .json()
        .await
        .map_err(|e| format!("invalid response: {e}"))?;

    if agents.is_empty() {
        println!("no agents");
        return Ok(());
    }

    println!(
        "{:<4} {:<9} {:<20} {:<36} {:<20}",
        "ID", "STATUS", "HOSTNAME", "FINGERPRINT", "CREATED_AT"
    );
    for agent in agents {
        println!(
            "{:<4} {:<9} {:<20} {:<36} {:<20}",
            agent.id, agent.status, agent.hostname, agent.fingerprint, agent.created_at
        );
    }
    Ok(())
}

async fn approve(client: &reqwest::Client, base: &str, id: i64) -> Result<(), String> {
    let resp: ApproveResponse = client
        .post(format!("{base}/agents/{id}/approve"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("server error: {e}"))?
        .json()
        .await
        .map_err(|e| format!("invalid response: {e}"))?;

    println!("approved agent {id}, token: {}", resp.token);
    Ok(())
}

async fn revoke(client: &reqwest::Client, base: &str, id: i64) -> Result<(), String> {
    client
        .post(format!("{base}/agents/{id}/revoke"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("server error: {e}"))?;

    println!("revoked agent {id}");
    Ok(())
}

async fn remove(client: &reqwest::Client, base: &str, id: i64) -> Result<(), String> {
    client
        .delete(format!("{base}/agents/{id}"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("server error: {e}"))?;

    println!("removed agent {id}");
    Ok(())
}
