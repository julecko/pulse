//! `pulse-server user ...` — manage API accounts for the pulse app.
//!
//! This lives outside the shared `pulse-cli` command set (which `agent-cli` also
//! uses) because it needs the `server` crate and its SQLite dependency.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};

use pulse_server::admin;

#[derive(Parser)]
#[command(
    name = "pulse-server user",
    about = "Manage API accounts for the pulse app"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create an account (prompts for a password).
    Add { name: String },
    /// Change an account's password (prompts).
    Passwd { name: String },
    /// List accounts.
    List,
    /// Delete an account and all of its sessions.
    Rm { name: String },
}

/// `args` is everything after the `user` token.
pub fn run(app: pulse_cli::App, args: Vec<OsString>) -> ExitCode {
    let argv = std::iter::once(OsString::from("pulse-server user")).chain(args);
    let cli = match Cli::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(err) => {
            let _ = err.print();
            return if err.use_stderr() {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            };
        }
    };

    let db = match db_path() {
        Ok(p) => p,
        Err(e) => return fail(e),
    };

    let result = match cli.cmd {
        Cmd::Add { name } => match read_new_password(&name) {
            Ok(pw) => admin::add_user(&db, &name, &pw)
                .map(|()| {
                    chown_db(&db, app.service_user);
                    println!("created account {name:?}");
                })
                .map_err(|e| e.to_string()),
            Err(e) => Err(e),
        },
        Cmd::Passwd { name } => match read_new_password(&name) {
            Ok(pw) => admin::set_password(&db, &name, &pw)
                .map(|()| println!("updated password for {name:?}"))
                .map_err(|e| e.to_string()),
            Err(e) => Err(e),
        },
        Cmd::Rm { name } => admin::remove_user(&db, &name)
            .map(|()| println!("deleted account {name:?}"))
            .map_err(|e| e.to_string()),
        Cmd::List => admin::list_users(&db)
            .map(|users| {
                if users.is_empty() {
                    println!("no accounts");
                } else {
                    for (name, created_ms) in users {
                        println!("{name:<24} created {}", iso_utc(created_ms));
                    }
                }
            })
            .map_err(|e| e.to_string()),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}

fn fail(msg: impl std::fmt::Display) -> ExitCode {
    eprintln!("pulse-server: {msg}");
    ExitCode::FAILURE
}

fn db_path() -> Result<PathBuf, String> {
    let loaded = pulse_config::load::<pulse_server::Config>("server").map_err(|e| e.to_string())?;
    Ok(pulse_server::history_db_path(&loaded.config))
}

/// Obtain a new password. On a terminal, prompt twice (no echo) and require the
/// entries to match. Otherwise (piped/automated) read a single line from stdin.
/// The strength check itself happens in `admin`.
fn read_new_password(name: &str) -> Result<String, String> {
    use std::io::IsTerminal;

    if std::io::stdin().is_terminal() {
        let pw = rpassword::prompt_password(format!("New password for {name:?}: "))
            .map_err(|e| format!("reading password: {e}"))?;
        let again = rpassword::prompt_password("Repeat password: ")
            .map_err(|e| format!("reading password: {e}"))?;
        if pw != again {
            return Err("passwords do not match".into());
        }
        Ok(pw)
    } else {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("reading password from stdin: {e}"))?;
        let pw = line.trim_end_matches(['\r', '\n']).to_string();
        if pw.is_empty() {
            return Err("no password on stdin".into());
        }
        Ok(pw)
    }
}

/// Best-effort `chown pulse:pulse` on the DB and its WAL sidecars, so a root-run
/// `user add` that just created the file doesn't lock out the daemon.
fn chown_db(db: &Path, service_user: Option<&str>) {
    let Some(user) = service_user else { return };
    for suffix in ["", "-wal", "-shm"] {
        let path = if suffix.is_empty() {
            db.to_path_buf()
        } else {
            let mut s = db.as_os_str().to_os_string();
            s.push(suffix);
            PathBuf::from(s)
        };
        if path.exists() {
            let _ = Command::new("chown")
                .arg(format!("{user}:{user}"))
                .arg(&path)
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` from unix milliseconds (no chrono).
fn iso_utc(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (h, m, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);

    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}
