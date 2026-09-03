//! `pulse-<role> cert ...` — mutual-TLS certificate management.
//!
//! Files live in a `tls/` subfolder of the config directory (created by
//! `cert generate`; falls back to the flat config dir for pre-`tls/` installs):
//!   server: `tls/server.crt` `tls/server.key` `tls/trusted-agents/*.crt`
//!   agent:  `tls/agent.crt`  `tls/agent.key`  `tls/trusted-server.crt`

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::{App, CertCmd, Role};

const SERVER_CERT: &str = "server.crt";
const SERVER_KEY: &str = "server.key";
const AGENT_CERT: &str = "agent.crt";
const AGENT_KEY: &str = "agent.key";
const TRUSTED_SERVER: &str = "trusted-server.crt";
const TRUSTED_AGENTS: &str = "trusted-agents";

pub fn run<C>(app: App, action: CertCmd) -> Result<ExitCode, String>
where
    C: Serialize + DeserializeOwned + Default,
{
    match action {
        CertCmd::Generate { dns, ip, force } => generate(app, &dns, &ip, force),
        CertCmd::Fingerprint => {
            println!("{}", fingerprint_of(&own_cert(app))?);
            Ok(ExitCode::SUCCESS)
        }
        CertCmd::Pem => {
            let path = own_cert(app);
            print!(
                "{}",
                fs::read_to_string(&path)
                    .map_err(|e| format!("reading {}: {e}", path.display()))?
            );
            Ok(ExitCode::SUCCESS)
        }
        CertCmd::Trust { path } => trust::<C>(app, &path),
        CertCmd::Approve { path, name } => approve::<C>(app, &path, name.as_deref()),
        CertCmd::List => list(app),
        CertCmd::Revoke { id } => revoke(app, &id),
    }
}

/// Directory holding this role's TLS material. Resolves to `<config dir>/tls/`
/// once it exists (created by `cert generate`), otherwise the flat config dir so
/// deployments on the old layout keep working.
fn tls_dir(app: App) -> PathBuf {
    pulse_config::tls_dir(app.name)
}

fn own_cert(app: App) -> PathBuf {
    tls_dir(app).join(match app.role {
        Role::Server => SERVER_CERT,
        Role::Agent => AGENT_CERT,
    })
}

fn own_key(app: App) -> PathBuf {
    tls_dir(app).join(match app.role {
        Role::Server => SERVER_KEY,
        Role::Agent => AGENT_KEY,
    })
}

fn generate(app: App, dns: &[String], ip: &[String], force: bool) -> Result<ExitCode, String> {
    // New certs always land in the dedicated `tls/` subfolder. Creating it here
    // also makes `tls_dir()` (and every later `cert` command) resolve to it.
    let dir = app.dir().join("tls");
    fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;

    let cert_path = own_cert(app);
    let key_path = own_key(app);
    let legacy_cert = app.dir().join(cert_path.file_name().unwrap_or_default());
    let legacy_key = app.dir().join(key_path.file_name().unwrap_or_default());
    if !force
        && (cert_path.exists() || key_path.exists() || legacy_cert.exists() || legacy_key.exists())
    {
        return Err(format!(
            "{} or {} already exists (use --force)",
            cert_path.display(),
            key_path.display()
        ));
    }

    let (cert_pem, key_pem) = self_signed(app.role, dns, ip)?;
    write_mode(&cert_path, cert_pem.as_bytes(), 0o644)?;
    write_mode(&key_path, key_pem.as_bytes(), 0o600)?;
    if let Some(user) = app.service_user {
        chown_to(&dir, user);
        chown_to(&cert_path, user);
        chown_to(&key_path, user);
    }

    println!("wrote {}", cert_path.display());
    println!("wrote {}  (private key, mode 0600)", key_path.display());
    println!("fingerprint: {}", fingerprint_of(&cert_path)?);
    println!();
    match app.role {
        Role::Server => {
            println!("next:");
            println!("  - hand this cert to agents:  pulse-server cert pem");
            println!(
                "  - approve each agent:        pulse-server cert approve <agent.crt> --name <id>"
            );
            println!("    (approving the first agent turns TLS on)");
        }
        Role::Agent => {
            println!("next:");
            println!("  - send this cert to the server admin:  pulse-agent cert pem");
            println!("  - pin the server:                     pulse-agent cert trust <server.crt>");
            println!("    (trusting the server turns TLS on)");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn trust<C>(app: App, src: &Path) -> Result<ExitCode, String>
where
    C: Serialize + DeserializeOwned + Default,
{
    if app.role != Role::Agent {
        return Err("`cert trust` is an agent command".into());
    }
    if !own_cert(app).exists() || !own_key(app).exists() {
        return Err("run `pulse-agent cert generate` first".into());
    }
    let certs = pulse_config::tls::load_certs(src).map_err(|e| e.to_string())?;
    let fp = pulse_config::tls::fingerprint(&certs[0]);
    let pem = fs::read(src).map_err(|e| format!("reading {}: {e}", src.display()))?;

    let dir = tls_dir(app);
    let dest = dir.join(TRUSTED_SERVER);
    fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    write_mode(&dest, &pem, 0o644)?;

    super::apply_sets::<C>(&pulse_config::path(app.name), &[("tls", "true")])?;

    println!("pinned server cert -> {}", dest.display());
    println!("fingerprint: {fp}");
    println!("must match `pulse-server cert fingerprint` on the server");
    println!("TLS enabled — restart the agent to apply");
    Ok(ExitCode::SUCCESS)
}

fn approve<C>(app: App, src: &Path, name: Option<&str>) -> Result<ExitCode, String>
where
    C: Serialize + DeserializeOwned + Default,
{
    if app.role != Role::Server {
        return Err("`cert approve` is a server command".into());
    }
    if !own_cert(app).exists() || !own_key(app).exists() {
        return Err("run `pulse-server cert generate` first".into());
    }
    let certs = pulse_config::tls::load_certs(src).map_err(|e| e.to_string())?;
    let fp = pulse_config::tls::fingerprint(&certs[0]);
    let pem = fs::read(src).map_err(|e| format!("reading {}: {e}", src.display()))?;

    let stem = match name {
        Some(n) => sanitize(n),
        None => fp
            .trim_start_matches("sha256:")
            .replace(':', "")
            .to_lowercase(),
    };
    let store = tls_dir(app).join(TRUSTED_AGENTS);
    fs::create_dir_all(&store).map_err(|e| format!("creating {}: {e}", store.display()))?;
    if let Some(user) = app.service_user {
        chown_to(&store, user);
    }
    let dest = store.join(format!("{stem}.crt"));
    write_mode(&dest, &pem, 0o644)?;
    if let Some(user) = app.service_user {
        chown_to(&dest, user);
    }

    super::apply_sets::<C>(&pulse_config::path(app.name), &[("tls", "true")])?;

    println!("approved {} -> {}", stem, dest.display());
    println!("fingerprint: {fp}");
    println!("TLS enabled — restart the server to apply");
    Ok(ExitCode::SUCCESS)
}

fn list(app: App) -> Result<ExitCode, String> {
    if app.role != Role::Server {
        return Err("`cert list` is a server command".into());
    }
    let store = tls_dir(app).join(TRUSTED_AGENTS);
    let entries = match fs::read_dir(&store) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("no approved agents ({} does not exist)", store.display());
            return Ok(ExitCode::SUCCESS);
        }
        Err(e) => return Err(format!("reading {}: {e}", store.display())),
    };
    let mut rows: Vec<(String, String)> = Vec::new();
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().is_some_and(|x| x == "crt") {
            let stem = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            rows.push((stem, fingerprint_of(&path)?));
        }
    }
    rows.sort();
    if rows.is_empty() {
        println!("no approved agents");
    } else {
        for (name, fp) in rows {
            println!("{name:<24} {fp}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn revoke(app: App, id: &str) -> Result<ExitCode, String> {
    if app.role != Role::Server {
        return Err("`cert revoke` is a server command".into());
    }
    let store = tls_dir(app).join(TRUSTED_AGENTS);
    let entries = fs::read_dir(&store).map_err(|e| format!("reading {}: {e}", store.display()))?;
    let mut removed = 0;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if !path.extension().is_some_and(|x| x == "crt") {
            continue;
        }
        let stem = path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let fp = fingerprint_of(&path)?;
        if stem == id || fp == id || fp.to_lowercase().contains(&id.to_lowercase()) {
            fs::remove_file(&path).map_err(|e| format!("removing {}: {e}", path.display()))?;
            println!("revoked {stem}");
            removed += 1;
        }
    }
    if removed == 0 {
        return Err(format!("no approved agent matches {id:?}"));
    }
    let left = fs::read_dir(&store)
        .map(|e| {
            e.filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|x| x == "crt"))
                .count()
        })
        .unwrap_or(0);
    if left == 0 {
        println!(
            "warning: no approved agents remain — the server will refuse to start with tls=true"
        );
    }
    println!("restart the server to apply");
    Ok(ExitCode::SUCCESS)
}

fn fingerprint_of(cert_path: &Path) -> Result<String, String> {
    let certs = pulse_config::tls::load_certs(cert_path).map_err(|e| e.to_string())?;
    Ok(pulse_config::tls::fingerprint(&certs[0]))
}

/// A self-signed leaf good for ~20 years. Server certs also carry SAN
/// `DNS:pulse` (the name the agent's verifier is handed).
fn self_signed(role: Role, dns: &[String], ip: &[String]) -> Result<(String, String), String> {
    let mut names = Vec::new();
    if role == Role::Server {
        names.push(pulse_config::tls::PIN_SERVER_NAME.to_string());
    }
    names.extend(dns.iter().cloned());

    let mut params =
        rcgen::CertificateParams::new(names).map_err(|e| format!("cert params: {e}"))?;
    for addr in ip {
        let parsed: std::net::IpAddr = addr
            .parse()
            .map_err(|_| format!("not an IP address: {addr}"))?;
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(parsed));
    }
    let cn = match role {
        Role::Server => "pulse-server",
        Role::Agent => "pulse-agent",
    };
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2040, 1, 1);

    let key = rcgen::KeyPair::generate().map_err(|e| format!("key generation: {e}"))?;
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("self-signing: {e}"))?;
    Ok((cert.pem(), key.serialize_pem()))
}

fn write_mode(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    fs::write(path, data).map_err(|e| format!("writing {}: {e}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {}: {e}", path.display()))
}

/// Best effort `chown user:user path` (silent — harmless when not root).
fn chown_to(path: &Path, user: &str) {
    let _ = std::process::Command::new("chown")
        .arg(format!("{user}:{user}"))
        .arg(path)
        .stderr(std::process::Stdio::null())
        .status();
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}
