//! `pulse-<role> cert ...` — self-signed certificate generation (server) and
//! trust/pinning (agent).

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::{App, CertCmd, Tls};

pub fn run<C>(app: App, action: CertCmd) -> Result<ExitCode, String>
where
    C: Serialize + DeserializeOwned + Default,
{
    match action {
        CertCmd::Generate { dns, ip, force } => generate::<C>(app, &dns, &ip, force),
        CertCmd::Trust { path } => trust::<C>(app, &path),
        CertCmd::Fingerprint => {
            println!("{}", fingerprint_of(&active_cert(app))?);
            Ok(ExitCode::SUCCESS)
        }
        CertCmd::Path => {
            println!("{}", active_cert(app).display());
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Path of the certificate this role reads at runtime.
fn active_cert(app: App) -> PathBuf {
    let name = match app.tls {
        Tls::Server { cert, .. } | Tls::Agent { cert } => cert,
    };
    app.dir().join(name)
}

fn generate<C>(app: App, dns: &[String], ip: &[String], force: bool) -> Result<ExitCode, String>
where
    C: Serialize + DeserializeOwned + Default,
{
    let (cert_name, key_name) = match app.tls {
        Tls::Server { cert, key } => (cert, key),
        Tls::Agent { .. } => {
            return Err("`cert generate` is a server command; agents use `cert trust`".into());
        }
    };

    let dir = app.dir();
    let cert_path = dir.join(cert_name);
    let key_path = dir.join(key_name);
    if !force && (cert_path.exists() || key_path.exists()) {
        return Err(format!(
            "{} or {} already exists (use --force)",
            cert_path.display(),
            key_path.display()
        ));
    }

    let (cert_pem, key_pem) = self_signed(dns, ip)?;
    fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    write_mode(&cert_path, cert_pem.as_bytes(), 0o644)?;
    write_mode(&key_path, key_pem.as_bytes(), 0o600)?;
    if let Some(user) = app.service_user {
        chown_to(&cert_path, user);
        chown_to(&key_path, user);
    }

    let config = pulse_config::path(app.name);
    super::apply_sets::<C>(
        &config,
        &[
            ("tls.cert", &cert_path.to_string_lossy()),
            ("tls.key", &key_path.to_string_lossy()),
        ],
    )?;

    println!("wrote {}", cert_path.display());
    println!("wrote {}  (private key, mode 0600)", key_path.display());
    println!("fingerprint: {}", fingerprint_of(&cert_path)?);
    println!();
    println!("next:");
    println!("  1. restart the server");
    println!("  2. copy {} to each agent host", cert_path.display());
    println!("  3. on each agent:  pulse-agent cert trust <server.crt>");
    Ok(ExitCode::SUCCESS)
}

fn trust<C>(app: App, src: &Path) -> Result<ExitCode, String>
where
    C: Serialize + DeserializeOwned + Default,
{
    let cert_name = match app.tls {
        Tls::Agent { cert } => cert,
        Tls::Server { .. } => {
            return Err("`cert trust` is an agent command; servers use `cert generate`".into());
        }
    };

    // Validate it is a certificate PEM before installing.
    let certs = pulse_config::tls::load_certs(src).map_err(|e| e.to_string())?;
    let fp = pulse_config::tls::fingerprint(&certs[0]);
    let pem = fs::read(src).map_err(|e| format!("reading {}: {e}", src.display()))?;

    let dir = app.dir();
    let dest = dir.join(cert_name);
    fs::create_dir_all(&dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    write_mode(&dest, &pem, 0o644)?;

    let config = pulse_config::path(app.name);
    super::apply_sets::<C>(&config, &[("tls.cert", &dest.to_string_lossy())])?;

    println!("trusted {}", dest.display());
    println!("fingerprint: {fp}");
    println!("must match `pulse-server cert fingerprint` on the server");
    Ok(ExitCode::SUCCESS)
}

fn fingerprint_of(cert_path: &Path) -> Result<String, String> {
    let certs = pulse_config::tls::load_certs(cert_path).map_err(|e| e.to_string())?;
    Ok(pulse_config::tls::fingerprint(&certs[0]))
}

/// A self-signed leaf good for ~20 years. Always carries SAN `DNS:pulse`
/// (the name the agent pins against) plus any extras.
fn self_signed(dns: &[String], ip: &[String]) -> Result<(String, String), String> {
    let mut names = vec![pulse_config::tls::PIN_SERVER_NAME.to_string()];
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
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "pulse");
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

/// Best effort `chown user:user path` (silent — fails harmlessly when not root
/// or the user doesn't exist yet).
fn chown_to(path: &Path, user: &str) {
    let _ = std::process::Command::new("chown")
        .arg(format!("{user}:{user}"))
        .arg(path)
        .stderr(std::process::Stdio::null())
        .status();
}
