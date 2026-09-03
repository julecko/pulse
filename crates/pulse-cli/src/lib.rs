//! Shared config & control front-end for the pulse daemons.
//!
//! `server-cli` and `agent-cli` are thin `main`s over [`run`], differing only
//! by the [`App`] descriptor and the config type `C`.

use std::ffi::OsString;
use std::fs;
use std::io::{ErrorKind, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Per-daemon descriptor supplied by each front-end binary.
#[derive(Clone, Copy)]
pub struct App {
    /// Config basename passed to `pulse_config` (`<name>.toml`).
    pub name: &'static str,
    /// systemd unit name, also used as the CLI program name in help output.
    pub unit: &'static str,
    /// Installed daemon path, used by `run`.
    pub daemon: &'static str,
}

#[derive(Parser)]
#[command(
    about = "Configure and control the pulse daemon",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Inspect or modify configuration.
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
    /// `systemctl start` the service.
    Start,
    /// `systemctl stop` the service.
    Stop,
    /// `systemctl restart` the service.
    Restart,
    /// `systemctl status` the service.
    Status,
    /// `systemctl enable --now` the service.
    Enable,
    /// `systemctl disable --now` the service.
    Disable,
    /// Run the daemon in the foreground (replaces this process).
    Run,
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Print the resolved config file path.
    Path,
    /// Print the effective configuration (file merged over defaults).
    Show,
    /// Parse and validate the config file.
    Check,
    /// Write a default config file if none exists.
    Init {
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
    /// Edit the config file in $EDITOR, validating before saving.
    Edit,
    /// Set a key, e.g. `config set bind 0.0.0.0:9000` or `config set log.level debug`.
    Set { key: String, value: String },
}

/// Entry point for a front-end binary.
pub fn run<C>(app: App) -> ExitCode
where
    C: Serialize + DeserializeOwned + Default,
{
    let cli = match Cli::try_parse_from(program_args(app.unit)) {
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

    let result = match cli.cmd {
        Cmd::Config { action } => config_cmd::<C>(app, action),
        Cmd::Start => systemctl(&["start", app.unit]),
        Cmd::Stop => systemctl(&["stop", app.unit]),
        Cmd::Restart => systemctl(&["restart", app.unit]),
        Cmd::Status => systemctl(&["status", app.unit]),
        Cmd::Enable => systemctl(&["enable", "--now", app.unit]),
        Cmd::Disable => systemctl(&["disable", "--now", app.unit]),
        Cmd::Run => run_daemon(app),
    };

    match result {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("{}: {msg}", app.unit);
            ExitCode::FAILURE
        }
    }
}

/// Rewrite argv[0] so clap's help/usage shows the real program name.
fn program_args(name: &str) -> Vec<OsString> {
    let mut args: Vec<OsString> = std::env::args_os().collect();
    match args.first_mut() {
        Some(first) => *first = name.into(),
        None => args.push(name.into()),
    }
    args
}

fn config_cmd<C>(app: App, action: ConfigCmd) -> Result<ExitCode, String>
where
    C: Serialize + DeserializeOwned + Default,
{
    let path = pulse_config::path(app.name);

    match action {
        ConfigCmd::Path => {
            println!("{}", path.display());
            Ok(ExitCode::SUCCESS)
        }

        ConfigCmd::Show => {
            let loaded = pulse_config::load::<C>(app.name).map_err(|e| e.to_string())?;
            let body = toml::to_string_pretty(&loaded.config).map_err(|e| e.to_string())?;
            let source = if loaded.found {
                format!("file {}", loaded.path.display())
            } else {
                "built-in defaults".to_string()
            };
            println!("# effective {} config ({source})", app.name);
            print!("{body}");
            Ok(ExitCode::SUCCESS)
        }

        ConfigCmd::Check => match pulse_config::load::<C>(app.name) {
            Ok(l) if l.found => {
                println!("ok: {}", l.path.display());
                Ok(ExitCode::SUCCESS)
            }
            Ok(l) => {
                println!(
                    "ok: no file at {} (built-in defaults are valid)",
                    l.path.display()
                );
                Ok(ExitCode::SUCCESS)
            }
            Err(e) => {
                eprintln!("invalid: {e}");
                Ok(ExitCode::FAILURE)
            }
        },

        ConfigCmd::Init { force } => {
            if path.exists() && !force {
                return Err(format!("{} already exists (use --force)", path.display()));
            }
            let body = toml::to_string_pretty(&C::default()).map_err(|e| e.to_string())?;
            write_atomic(&path, &body)?;
            println!("wrote {}", path.display());
            Ok(ExitCode::SUCCESS)
        }

        ConfigCmd::Edit => edit_config::<C>(&path),
        ConfigCmd::Set { key, value } => set_key::<C>(&path, &key, &value),
    }
}

fn edit_config<C>(path: &Path) -> Result<ExitCode, String>
where
    C: Serialize + DeserializeOwned + Default,
{
    let seed = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            toml::to_string_pretty(&C::default()).map_err(|e| e.to_string())?
        }
        Err(e) => return Err(format!("reading {}: {e}", path.display())),
    };

    let editor = std::env::var_os("VISUAL")
        .or_else(|| std::env::var_os("EDITOR"))
        .unwrap_or_else(|| "vi".into());

    let tmp = path.with_file_name(format!(
        "{}.new",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    fs::write(&tmp, &seed).map_err(|e| format!("writing {}: {e}", tmp.display()))?;

    let outcome = loop {
        let status = Command::new(&editor).arg(&tmp).status();
        match status {
            Ok(s) if s.success() => {}
            Ok(_) => break Err("editor exited non-zero; config unchanged".to_string()),
            Err(e) => break Err(format!("launching editor {editor:?}: {e}")),
        }

        let edited = match fs::read_to_string(&tmp) {
            Ok(s) => s,
            Err(e) => break Err(e.to_string()),
        };
        match toml::from_str::<C>(&edited) {
            Ok(_) => {
                break fs::rename(&tmp, path)
                    .map(|()| {
                        println!("saved {}", path.display());
                        ExitCode::SUCCESS
                    })
                    .map_err(|e| format!("saving {}: {e}", path.display()));
            }
            Err(e) => {
                eprintln!("invalid config: {e}");
                if !prompt_retry() {
                    break Err("aborted; config unchanged".to_string());
                }
            }
        }
    };

    if outcome.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    outcome
}

fn set_key<C>(path: &Path, key: &str, value: &str) -> Result<ExitCode, String>
where
    C: Serialize + DeserializeOwned + Default,
{
    let source = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            toml::to_string_pretty(&C::default()).map_err(|e| e.to_string())?
        }
        Err(e) => return Err(format!("reading {}: {e}", path.display())),
    };

    let mut doc = source
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| format!("parsing {}: {e}", path.display()))?;

    let parts: Vec<&str> = key.split('.').collect();
    let (last, parents) = parts.split_last().expect("key is non-empty");
    let mut node = doc.as_item_mut();
    for parent in parents {
        node = &mut node[parent];
    }
    node[last] = infer_value(value);

    let candidate = doc.to_string();
    toml::from_str::<C>(&candidate)
        .map_err(|e| format!("`{key} = {value}` would produce an invalid config: {e}"))?;

    write_atomic(path, &candidate)?;
    println!("{}: {key} = {value}", path.display());
    Ok(ExitCode::SUCCESS)
}

/// Best-effort scalar typing for `config set` values.
fn infer_value(raw: &str) -> toml_edit::Item {
    use toml_edit::value;
    if let Ok(b) = raw.parse::<bool>() {
        value(b)
    } else if let Ok(i) = raw.parse::<i64>() {
        value(i)
    } else if let Ok(f) = raw.parse::<f64>() {
        value(f)
    } else {
        value(raw)
    }
}

fn run_daemon(app: App) -> Result<ExitCode, String> {
    // exec only returns if it failed.
    Err(format!(
        "exec {}: {}",
        app.daemon,
        Command::new(app.daemon).exec()
    ))
}

fn systemctl(args: &[&str]) -> Result<ExitCode, String> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .map_err(|e| format!("running systemctl: {e}"))?;
    Ok(match status.code() {
        Some(0) => ExitCode::SUCCESS,
        Some(c) => ExitCode::from(c as u8),
        None => ExitCode::FAILURE,
    })
}

fn prompt_retry() -> bool {
    print!("re-edit? [Y/n] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    !matches!(line.trim().to_ascii_lowercase().as_str(), "n" | "no")
}

/// Write `body` to `path` via a temp file + rename, creating parent dirs.
fn write_atomic(path: &Path, body: &str) -> Result<(), String> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    }
    let tmp = path.with_file_name(format!(
        "{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    fs::write(&tmp, body).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("saving {}: {e}", path.display()))
}
