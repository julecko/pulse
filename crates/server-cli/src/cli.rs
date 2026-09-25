use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "server-cli", about = "Admin CLI for the Pulse server")]
pub struct Cli {
    /// Pulse server address (host:port)
    #[arg(long, global = true, default_value = "127.0.0.1:8443")]
    pub server: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Check server health (GET /healthz)
    Health,
    /// Manage agents
    Agents {
        #[command(subcommand)]
        command: AgentsCommand,
    },
}

#[derive(Subcommand)]
pub enum AgentsCommand {
    /// List all agents (pending, approved, revoked)
    List,
    /// Approve a pending agent, printing the issued token
    Approve { id: i64 },
    /// Revoke an agent's access
    Revoke { id: i64 },
    /// Delete an agent entirely, so it can pair again as a fresh request
    Remove { id: i64 },
    /// Show an agent's most recent PAM events (logins, sudo, failed auth)
    Events { id: i64 },
}
