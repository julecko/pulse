use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum, error::ErrorKind};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};
use sysinfo::System;

use protocol::{CustomEvent, HostInfo, Metrics, Report, ReportEvent, SshLogin, Warning};

#[derive(Parser)]
#[command(name = "pulse-agent report", about = "Send a one-shot event report")]
struct ReportCli {
    #[command(subcommand)]
    command: ReportCommand,
}

#[derive(Subcommand)]
enum ReportCommand {
    /// Send an accepted or rejected SSH login event.
    SshLogin(SshLoginArgs),
    /// Send a warning event.
    Warning(WarningArgs),
    /// Send an application-specific event.
    Custom(CustomArgs),
}

#[derive(Args)]
struct SshLoginArgs {
    #[arg(long)]
    username: String,
    #[arg(long)]
    source: String,
    #[arg(long, default_value = "publickey")]
    auth_method: String,
    #[arg(long, value_enum, default_value_t = LoginOutcome::Success)]
    outcome: LoginOutcome,
}

#[derive(Clone, Copy, ValueEnum)]
enum LoginOutcome {
    Success,
    Failure,
}

#[derive(Args)]
struct WarningArgs {
    #[arg(long)]
    code: String,
    #[arg(long)]
    message: String,
    #[arg(long)]
    details: Option<String>,
}

#[derive(Args)]
struct CustomArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    message: String,
    /// Additional string field in KEY=VALUE form. May be repeated.
    #[arg(long = "field", value_parser = parse_field)]
    fields: Vec<(String, String)>,
}

fn main() -> ExitCode {
    let mut args = std::env::args_os();
    let _ = args.next();
    match args.next() {
        Some(command) if command == "report" => {
            let argv = std::env::args_os().skip(2).collect::<Vec<_>>();
            return match send_report(argv) {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => {
                    eprintln!("pulse-agent report: {err}");
                    ExitCode::FAILURE
                }
            };
        }
        _ => {}
    }

    pulse_cli::run::<pulse_agent::Config>(pulse_cli::App {
        name: "agent",
        unit: "pulse-agent",
        daemon: "/usr/lib/pulse/pulse-agentd",
        role: pulse_cli::Role::Agent,
        service_user: Some("pulse"),
        extra_subcommand: Some(("report", "Send a one-shot event report")),
    })
}

fn send_report(args: Vec<std::ffi::OsString>) -> Result<(), String> {
    let cli = match ReportCli::try_parse_from(
        std::iter::once(std::ffi::OsString::from("pulse-agent report")).chain(args),
    ) {
        Ok(cli) => cli,
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            print!("{err}");
            return Ok(());
        }
        Err(err) => return Err(err.to_string()),
    };

    let event = match cli.command {
        ReportCommand::SshLogin(args) => ReportEvent::SshLogin(SshLogin {
            username: args.username,
            source: args.source,
            success: matches!(args.outcome, LoginOutcome::Success),
            auth_method: args.auth_method,
        }),
        ReportCommand::Warning(args) => ReportEvent::Warning(Warning {
            code: args.code,
            message: args.message,
            details: args.details,
        }),
        ReportCommand::Custom(args) => ReportEvent::Custom(CustomEvent {
            name: args.name,
            message: args.message,
            fields: args.fields.into_iter().collect(),
        }),
    };

    let loaded =
        pulse_config::load::<pulse_agent::Config>("agent").map_err(|err| err.to_string())?;
    let report = Report::new(host_info()?, Metrics::default()).with_events(vec![event]);
    report.validate().map_err(|err| err.to_string())?;
    send(&loaded.config, &report)
}

fn parse_field(raw: &str) -> Result<(String, String), String> {
    let (key, value) = raw
        .split_once('=')
        .ok_or_else(|| "field must use KEY=VALUE".to_string())?;
    if key.is_empty() {
        return Err("field key cannot be empty".into());
    }
    Ok((key.to_string(), value.to_string()))
}

fn host_info() -> Result<HostInfo, String> {
    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());
    let machine_id = ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .find_map(|path| std::fs::read_to_string(path).ok())
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .ok_or_else(|| "could not determine machine id".to_string())?;
    Ok(HostInfo {
        machine_id,
        hostname,
        os: System::name(),
        os_version: System::os_version(),
        kernel_version: System::kernel_version(),
    })
}

fn send(cfg: &pulse_agent::Config, report: &Report) -> Result<(), String> {
    let tcp = TcpStream::connect(&cfg.server).map_err(|err| format!("connect: {err}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|err| format!("set timeout: {err}"))?;

    if cfg.tls {
        let dir = pulse_config::tls_dir("agent");
        let config = pulse_config::tls::pinned_client_config(
            &dir.join("trusted-server.crt"),
            &dir.join("agent.crt"),
            &dir.join("agent.key"),
        )
        .map_err(|err| format!("tls: {err}"))?;
        let name = ServerName::try_from(pulse_config::tls::PIN_SERVER_NAME)
            .map_err(|err| format!("tls server name: {err}"))?;
        let conn = ClientConnection::new(config, name).map_err(|err| format!("tls: {err}"))?;
        let mut stream = StreamOwned::new(conn, tcp);
        protocol::write_report(&mut stream, report).map_err(|err| format!("send: {err}"))?;
        stream.conn.send_close_notify();
        stream.flush().map_err(|err| format!("flush: {err}"))?;
        drain_to_eof(&mut stream).map_err(|err| format!("receive: {err}"))
    } else {
        let mut stream = tcp;
        protocol::write_report(&mut stream, report).map_err(|err| format!("send: {err}"))?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|err| format!("shutdown: {err}"))?;
        drain_to_eof(&mut stream).map_err(|err| format!("receive: {err}"))
    }
}

fn drain_to_eof<S: Read>(stream: &mut S) -> io::Result<()> {
    let mut sink = [0u8; 256];
    loop {
        match stream.read(&mut sink) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        }
    }
}
