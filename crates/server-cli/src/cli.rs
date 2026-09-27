use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use protocol::{
    AlertMetric, AlertOperator, AlertSeverity, AuthEventKind, MAX_RETENTION_DAYS, RetentionData,
};

#[derive(Parser)]
#[command(name = "pulse-server-cli", about = "Admin CLI for the Pulse server")]
pub struct Cli {
    /// Pulse server address (host:port)
    #[arg(long, global = true, default_value = "127.0.0.1:8443")]
    pub server: String,

    /// Certificate (PEM) to pin for the server: the only one trusted,
    /// replacing the built-in public CA roots. Default: the server's own
    /// cert (`[web.tls] cert` from the server config, else
    /// /etc/pulse-server/certs/cert.pem) when it's readable, trusted on top
    /// of the built-in roots.
    #[arg(long, global = true)]
    pub ca_cert: Option<PathBuf>,

    /// User to log in as for `agents`, `rules`, `alerts`, `geo-alerts`,
    /// `devices` and `retention` commands (prompted for if omitted).
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
    /// Manage alert rules: what fires an alert, and whether it's pushed
    /// (logs in first; see --user)
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// View and acknowledge alerts fired by rules (logs in first)
    Alerts {
        #[command(subcommand)]
        command: AlertsCommand,
    },
    /// Alert when an SSH login comes from a country that isn't allowed
    /// (needs a GeoIP database on the server; logs in first)
    GeoAlerts {
        #[command(subcommand)]
        command: GeoAlertsCommand,
    },
    /// Manage devices that get alert pushes; the mobile app registers them
    /// (logs in first)
    Devices {
        #[command(subcommand)]
        command: DevicesCommand,
    },
    /// How long the server keeps metrics, PAM events and resolved alerts
    /// (logs in first)
    Retention {
        #[command(subcommand)]
        command: RetentionCommand,
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
    /// Show, open or close pairing for new agents
    Pairing {
        #[command(subcommand)]
        command: PairingCommand,
    },
    /// Approve a pending agent (compare its fingerprint with
    /// `pulse-agent-cli fingerprint` on the host first)
    Approve { id: i64 },
    /// Revoke an agent's access
    Revoke { id: i64 },
    /// Restore a revoked agent's access with its existing secret. Only if
    /// you're sure the secret never leaked: anyone with a copy gets access
    /// back too. Otherwise `remove` it and reset its identity instead.
    Unrevoke { id: i64 },
    /// Delete an agent entirely, so it can pair again as a fresh request
    Remove { id: i64 },
    /// Show an agent's most recent PAM events (logins, sudo, failed auth)
    Events { id: i64 },
    /// Choose which of an agent's PAM events are pushed to every registered
    /// device (none by default; they're stored either way)
    PamNotify {
        #[command(subcommand)]
        command: PamNotifyCommand,
    },
    /// Alert (and push) when an agent sends no metrics for too long, e.g.
    /// its host is down or cut off
    OfflineAlert {
        #[command(subcommand)]
        command: OfflineAlertCommand,
    },
    /// Show an agent's most recent metrics snapshots
    Metrics {
        id: i64,
        /// How many snapshots to show (newest first)
        #[arg(long, default_value_t = 10)]
        limit: u32,
    },
}

#[derive(Subcommand)]
pub enum OfflineAlertCommand {
    /// Show every agent's limit, last metrics and whether it's offline
    List,
    /// Alert when agent ID sends no metrics for AFTER: 90s, 10m, 2h, 1d
    /// (1 minute to 30 days). Use a few of its metrics intervals (60s by
    /// default), e.g. 5m
    Set {
        id: i64,
        #[arg(value_parser = parse_duration)]
        after: u32,
    },
    /// Stop watching agent ID (resolves its offline alert, if any)
    Off { id: i64 },
}

#[derive(Subcommand)]
pub enum PamNotifyCommand {
    /// Show every agent's pushed PAM events
    List,
    /// Show one agent's pushed PAM events
    Show { id: i64 },
    /// Push these PAM events of agent ID, replacing its current choice:
    /// session_open (logins, sudo/su sessions), session_close (logouts),
    /// auth_failure (failed passwords)
    Set {
        id: i64,
        #[arg(required = true)]
        kinds: Vec<AuthEventKind>,
    },
    /// Stop pushing agent ID's PAM events
    Off { id: i64 },
}

#[derive(Subcommand)]
pub enum PairingCommand {
    /// Show whether new agents can pair
    Status,
    /// Let new agents send pairing requests (you still approve each one)
    Open {
        /// Close again automatically after this many minutes (1-10080).
        /// Default: stay open until `pairing close`
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=10080))]
        minutes: Option<u32>,
    },
    /// Stop accepting new pairing requests (known agents keep working)
    Close,
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

#[derive(Subcommand)]
pub enum RulesCommand {
    /// List all alert rules
    List,
    /// Add a rule, e.g. `rules add "CPU high" --metric cpu_usage_percent
    /// --op gt --threshold 90 --for 5m --severity critical --notify`
    Add {
        /// Shown in each alert's title: "<name> on <hostname>"
        name: String,
        /// cpu_usage_percent, memory_used_percent, swap_used_percent,
        /// disk_used_percent (fullest disk), load_avg_one, load_avg_five
        /// or load_avg_fifteen
        #[arg(long)]
        metric: AlertMetric,
        /// gt, ge, lt or le (or >, >=, <, <= quoted)
        #[arg(long)]
        op: AlertOperator,
        #[arg(long, allow_negative_numbers = true)]
        threshold: f64,
        /// Only watch this agent (default: every agent)
        #[arg(long)]
        agent: Option<i64>,
        /// Fire only once the condition has held this long: 90s, 5m, 1h, 1d,
        /// or plain seconds (default: at once)
        #[arg(long = "for", value_parser = parse_duration, default_value = "0")]
        duration_secs: u32,
        /// info, warning or critical
        #[arg(long, default_value = "warning")]
        severity: AlertSeverity,
        /// Push each alert it fires to every registered device
        #[arg(long)]
        notify: bool,
    },
    /// Start evaluating a rule again
    Enable { id: i64 },
    /// Stop evaluating a rule; its active alerts are resolved
    Disable { id: i64 },
    /// Turn pushing a rule's alerts on or off
    Notify { id: i64, state: OnOff },
    /// Delete a rule; its alerts are kept (resolved if still active)
    Remove { id: i64 },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum OnOff {
    On,
    Off,
}

#[derive(Subcommand)]
pub enum AlertsCommand {
    /// Show the most recent alerts, newest first
    List {
        /// Only alerts about this agent
        #[arg(long)]
        agent: Option<i64>,
        /// Only alerts that haven't resolved yet
        #[arg(long)]
        active: bool,
        /// How many to show
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
    /// Mark an alert as seen
    Ack { id: i64 },
}

#[derive(Subcommand)]
pub enum GeoAlertsCommand {
    /// Show the allowed countries and the server's GeoIP database
    Show,
    /// Turn geo alerts on: SSH logins from any other country (or one the
    /// database doesn't know) raise an alert. Replaces all settings
    Set {
        /// Allowed countries, as two-letter ISO codes: SK CZ AT
        #[arg(required = true)]
        countries: Vec<String>,
        /// Also alert on failed logins, not just successful ones (noisy on
        /// a server that's open to the internet)
        #[arg(long)]
        failures: bool,
        /// Only record the alerts, don't push them
        #[arg(long)]
        no_push: bool,
    },
    /// Turn geo alerts off
    Off,
}

#[derive(Subcommand)]
pub enum DevicesCommand {
    /// List every user's registered devices
    List,
    /// Stop pushing alerts to a device
    Remove { id: i64 },
}

#[derive(Subcommand)]
pub enum RetentionCommand {
    /// Show how long each kind of data is kept, and who changed it
    Show,
    /// Keep DATA (metrics, auth_events or alerts) for DAYS days; 0 keeps it
    /// forever. Lowering it deletes older data right away. Overrides the
    /// server config's [retention] until `retention reset`
    Set {
        data: RetentionData,
        #[arg(value_parser = clap::value_parser!(u32).range(0..=MAX_RETENTION_DAYS as i64))]
        days: u32,
    },
    /// Go back to the server config's [retention] default for DATA
    Reset { data: RetentionData },
}

/// `90s`, `5m`, `1h`, `2d`, or plain seconds.
fn parse_duration(s: &str) -> Result<u32, String> {
    let (digits, unit) = match s.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => (&s[..i], c),
        _ => (s, 's'),
    };
    let n: u32 = digits
        .parse()
        .map_err(|_| format!("invalid duration {s:?} (e.g. 90s, 5m, 1h)"))?;
    let factor = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        _ => return Err(format!("invalid duration unit in {s:?} (use s, m, h or d)")),
    };
    n.checked_mul(factor)
        .ok_or_else(|| format!("duration {s:?} is too long"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("0"), Ok(0));
        assert_eq!(parse_duration("90"), Ok(90));
        assert_eq!(parse_duration("90s"), Ok(90));
        assert_eq!(parse_duration("5m"), Ok(300));
        assert_eq!(parse_duration("2h"), Ok(7200));
        assert_eq!(parse_duration("2d"), Ok(172800));
        assert!(parse_duration("5w").is_err());
        assert!(parse_duration("m").is_err());
        assert!(parse_duration("").is_err());
    }
}
