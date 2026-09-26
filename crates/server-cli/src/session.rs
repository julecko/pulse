//! Logging in to the server for commands behind its user auth (everything
//! under `agents`). Each run logs in, runs one command, and logs out again,
//! so no session outlives the command.

use std::path::PathBuf;

use protocol::{LoginRequest, LoginResponse};
use pulse_shared::tls::TlsConfig;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use reqwest::{Certificate, StatusCode};
use serde::Deserialize;

use crate::prompt;

/// Just the `[web.tls]` section of the server config; everything else in
/// the file is ignored.
#[derive(Default, Deserialize)]
#[serde(default)]
struct ServerConfigTls {
    web: ServerConfigWeb,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct ServerConfigWeb {
    tls: TlsConfig,
}

/// The extra cert to trust for the server. `--ca-cert` must be readable;
/// without it, the server's own cert is used if this user can read it
/// (it usually can on the server host), else only the built-in roots.
pub fn ca_cert(explicit: Option<PathBuf>) -> Result<Option<Certificate>, String> {
    let (path, required) = match explicit {
        Some(path) => (path, true),
        None => match pulse_shared::config::load::<ServerConfigTls>("server") {
            Ok(cfg) => (cfg.web.tls.resolved_cert(), false),
            Err(_) => return Ok(None),
        },
    };
    let pem = match std::fs::read(&path) {
        Ok(pem) => pem,
        Err(_) if !required => return Ok(None),
        Err(e) => return Err(format!("reading --ca-cert {}: {e}", path.display())),
    };
    Certificate::from_pem(&pem)
        .map(Some)
        .map_err(|e| format!("parsing CA cert {}: {e}", path.display()))
}

/// Always verifies the server's cert: against the built-in public CA
/// roots, plus `ca_cert` (see [`ca_cert`]).
pub fn http_client(ca_cert: Option<&Certificate>, default_headers: HeaderMap) -> reqwest::Client {
    let mut builder = reqwest::Client::builder().default_headers(default_headers);
    if let Some(cert) = ca_cert {
        builder = builder.add_root_certificate(cert.clone());
    }
    builder.build().expect("failed to build HTTP client")
}

/// Formats a failed request with its whole source chain, since the useful
/// part (e.g. a rejected server cert) isn't in reqwest's own message, and
/// adds a hint for cert errors.
pub fn request_error(err: &reqwest::Error) -> String {
    let mut msg = format!("request failed: {err}");
    let mut source = std::error::Error::source(err);
    while let Some(err) = source {
        msg.push_str(&format!(": {err}"));
        source = err.source();
    }
    if msg.contains("certificate") {
        msg.push_str(
            "\nhint: pass the server's cert.pem with --ca-cert, and make sure it's valid for the address in --server",
        );
    }
    msg
}

pub struct Session {
    /// Sends the session token on every request.
    client: reqwest::Client,
    base: String,
}

impl Session {
    /// Logs in as `username` (prompted for if `None`), prompting for the
    /// password without echo.
    pub async fn login(
        base: &str,
        ca_cert: Option<&Certificate>,
        username: Option<String>,
    ) -> Result<Self, String> {
        let username = match username {
            Some(username) => username,
            None if prompt::stdin_is_terminal() => prompt::line("Username: ")?,
            // stdin is taken by the piped password, so it can't carry both.
            None => return Err("--user is required when stdin isn't a terminal".to_string()),
        };
        let password = prompt::password("Password: ")?;

        let resp = http_client(ca_cert, HeaderMap::new())
            .post(format!("{base}/auth/login"))
            .json(&LoginRequest { username, password })
            .send()
            .await
            .map_err(|e| request_error(&e))?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            return Err("login failed: invalid username or password".to_string());
        }
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            let retry = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("?");
            return Err(format!(
                "login failed: too many login attempts from this address; try again in {retry}s"
            ));
        }
        let login: LoginResponse = resp
            .error_for_status()
            .map_err(|e| format!("login failed: {e}"))?
            .json()
            .await
            .map_err(|e| format!("invalid login response: {e}"))?;

        let mut auth = HeaderValue::from_str(&format!("Bearer {}", login.token))
            .map_err(|e| format!("invalid token from server: {e}"))?;
        auth.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, auth);

        Ok(Self {
            client: http_client(ca_cert, headers),
            base: base.to_string(),
        })
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Ends the session server-side. Best effort: if it fails, the session
    /// still expires on its own after `session_ttl_hours`.
    pub async fn logout(self) {
        let _ = self
            .client
            .post(format!("{}/auth/logout", self.base))
            .send()
            .await;
    }
}
