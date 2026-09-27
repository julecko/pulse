//! Admin CLI for the Pulse server: list/approve/revoke/remove agents, view
//! their PAM events and metrics, manage alert rules, alerts, push devices
//! and data retention (as a logged-in user), check health, and manage user
//! accounts (directly in the server's database).

mod cli;
mod commands;
mod prompt;
mod session;

use clap::Parser;
use cli::{
    AgentsCommand, AlertsCommand, Cli, Command, DevicesCommand, GeoAlertsCommand, OnOff,
    PairingCommand, PamNotifyCommand, RetentionCommand, RulesCommand, UsersCommand,
};
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
        Command::Health => match session::ca_cert(cli.ca_cert) {
            Ok(ca_cert) => {
                let client = session::http_client(ca_cert.as_ref(), HeaderMap::new());
                commands::health::check(&client, &base).await
            }
            Err(err) => Err(err),
        },
        Command::Agents { command } => {
            run_session(&base, cli.ca_cert, cli.user, Authed::Agents(command)).await
        }
        Command::Rules { command } => {
            run_session(&base, cli.ca_cert, cli.user, Authed::Rules(command)).await
        }
        Command::Alerts { command } => {
            run_session(&base, cli.ca_cert, cli.user, Authed::Alerts(command)).await
        }
        Command::Devices { command } => {
            run_session(&base, cli.ca_cert, cli.user, Authed::Devices(command)).await
        }
        Command::GeoAlerts { command } => {
            run_session(&base, cli.ca_cert, cli.user, Authed::GeoAlerts(command)).await
        }
        Command::Retention { command } => {
            run_session(&base, cli.ca_cert, cli.user, Authed::Retention(command)).await
        }
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

/// Commands that run as a logged-in user.
enum Authed {
    Agents(AgentsCommand),
    Rules(RulesCommand),
    Alerts(AlertsCommand),
    Devices(DevicesCommand),
    GeoAlerts(GeoAlertsCommand),
    Retention(RetentionCommand),
}

/// Logs in, runs `command`, and logs out again.
async fn run_session(
    base: &str,
    ca_cert: Option<std::path::PathBuf>,
    user: Option<String>,
    command: Authed,
) -> Result<(), String> {
    let ca_cert = session::ca_cert(ca_cert)?;
    let session = Session::login(base, ca_cert.as_ref(), user).await?;
    let client = session.client();
    let result = match command {
        Authed::Agents(command) => run_agents(client, base, command).await,
        Authed::Rules(command) => run_rules(client, base, command).await,
        Authed::Alerts(command) => run_alerts(client, base, command).await,
        Authed::Devices(command) => run_devices(client, base, command).await,
        Authed::GeoAlerts(command) => {
            use commands::geo_alerts as g;
            match command {
                GeoAlertsCommand::Show => g::show(client, base).await,
                GeoAlertsCommand::Set {
                    countries,
                    failures,
                    no_push,
                } => g::set(client, base, countries, failures, !no_push).await,
                GeoAlertsCommand::Off => g::off(client, base).await,
            }
        }
        Authed::Retention(command) => run_retention(client, base, command).await,
    };
    session.logout().await;
    result
}

async fn run_agents(
    client: &reqwest::Client,
    base: &str,
    command: AgentsCommand,
) -> Result<(), String> {
    match command {
        AgentsCommand::List => commands::agents::list(client, base).await,
        AgentsCommand::Pairing { command } => match command {
            PairingCommand::Status => commands::agents::pairing_status(client, base).await,
            PairingCommand::Open { minutes } => {
                commands::agents::set_pairing(client, base, true, minutes).await
            }
            PairingCommand::Close => commands::agents::set_pairing(client, base, false, None).await,
        },
        AgentsCommand::Approve { id } => commands::agents::approve(client, base, id).await,
        AgentsCommand::Revoke { id } => commands::agents::revoke(client, base, id).await,
        AgentsCommand::Unrevoke { id } => commands::agents::unrevoke(client, base, id).await,
        AgentsCommand::Remove { id } => commands::agents::remove(client, base, id).await,
        AgentsCommand::Events { id } => commands::agents::events(client, base, id).await,
        AgentsCommand::Metrics { id, limit } => {
            commands::agents::metrics(client, base, id, limit).await
        }
        AgentsCommand::PamNotify { command } => {
            use commands::agents as a;
            match command {
                PamNotifyCommand::List => a::pam_notify_list(client, base).await,
                PamNotifyCommand::Show { id } => a::pam_notify_show(client, base, id).await,
                PamNotifyCommand::Set { id, kinds } => {
                    a::pam_notify_set(client, base, id, kinds).await
                }
                PamNotifyCommand::Off { id } => a::pam_notify_set(client, base, id, vec![]).await,
            }
        }
    }
}

async fn run_rules(
    client: &reqwest::Client,
    base: &str,
    command: RulesCommand,
) -> Result<(), String> {
    use commands::alerts as a;
    match command {
        RulesCommand::List => a::list_rules(client, base).await,
        RulesCommand::Add {
            name,
            metric,
            op,
            threshold,
            agent,
            duration_secs,
            severity,
            notify,
        } => {
            let rule = protocol::NewAlertRule {
                name,
                agent_id: agent,
                metric,
                operator: op,
                threshold,
                duration_secs,
                severity,
                notify,
            };
            a::add_rule(client, base, &rule).await
        }
        RulesCommand::Enable { id } => a::update_rule(client, base, id, Some(true), None).await,
        RulesCommand::Disable { id } => a::update_rule(client, base, id, Some(false), None).await,
        RulesCommand::Notify { id, state } => {
            a::update_rule(client, base, id, None, Some(matches!(state, OnOff::On))).await
        }
        RulesCommand::Remove { id } => a::remove_rule(client, base, id).await,
    }
}

async fn run_alerts(
    client: &reqwest::Client,
    base: &str,
    command: AlertsCommand,
) -> Result<(), String> {
    match command {
        AlertsCommand::List {
            agent,
            active,
            limit,
        } => commands::alerts::list_alerts(client, base, agent, active, limit).await,
        AlertsCommand::Ack { id } => commands::alerts::acknowledge(client, base, id).await,
    }
}

async fn run_devices(
    client: &reqwest::Client,
    base: &str,
    command: DevicesCommand,
) -> Result<(), String> {
    match command {
        DevicesCommand::List => commands::alerts::list_devices(client, base).await,
        DevicesCommand::Remove { id } => commands::alerts::remove_device(client, base, id).await,
    }
}

async fn run_retention(
    client: &reqwest::Client,
    base: &str,
    command: RetentionCommand,
) -> Result<(), String> {
    use commands::retention as r;
    match command {
        RetentionCommand::Show => r::show(client, base).await,
        RetentionCommand::Set { data, days } => r::set(client, base, data, Some(days)).await,
        RetentionCommand::Reset { data } => r::set(client, base, data, None).await,
    }
}
