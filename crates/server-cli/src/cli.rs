use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "pulse-server-cli", about = "Admin CLI for the Pulse server")]
pub struct Cli {
    /// Pulse server address (host:port)
    #[arg(long, global = true, default_value = "127.0.0.1:8443")]
    pub server: String,

    /// User to log in as for `agents` commands (prompted for if omitted).
    /// The password is always prompted for without echo, or read from
    /// stdin when piped.
    #[arg(long, short = 'u', global = true)]
    pub user: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Check server health (GET /healthz)
    Health,
    /// Manage agents (logs in first; see --user)
    Agents {
        #[command(subcommand)]
        command: AgentsCommand,
    },
    /// Manage user accounts. Opens the server's SQLite file directly
    /// (no HTTP), so it must run on the server host with write access to it.
    Users {
        /// Server database file. Default: `[db] path` from the server
        /// config, else the server's default location.
        #[arg(long)]
        db: Option<PathBuf>,

        #[command(subcommand)]
        command: UsersCommand,
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
    /// Show an agent's most recent metrics snapshots
    Metrics {
        id: i64,
        /// How many snapshots to show (newest first)
        #[arg(long, default_value_t = 10)]
        limit: u32,
    },
}

#[derive(Subcommand)]
pub enum UsersCommand {
    /// Create a user; prompts for the password (or reads one line from stdin)
    Add { username: String },
    /// Delete a user, ending all their sessions
    Remove { username: String },
    /// List users and their active session counts
    List,
}
