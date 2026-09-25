//! Logging in to the server for commands behind its user auth (everything
//! under `agents`). Each run logs in, runs one command, and logs out again,
//! so no session outlives the command.

use protocol::{LoginRequest, LoginResponse};
use reqwest::StatusCode;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

use crate::prompt;

/// Talks to the server's self-signed dev cert; there's no CA trust
/// distribution yet, same as the agent binary.
pub fn http_client(default_headers: HeaderMap) -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .default_headers(default_headers)
        .build()
        .expect("failed to build HTTP client")
}

pub struct Session {
    /// Sends the session token on every request.
    client: reqwest::Client,
    base: String,
}

impl Session {
    /// Logs in as `username` (prompted for if `None`), prompting for the
    /// password without echo.
    pub async fn login(base: &str, username: Option<String>) -> Result<Self, String> {
        let username = match username {
            Some(username) => username,
            None if prompt::stdin_is_terminal() => prompt::line("Username: ")?,
            // stdin is taken by the piped password, so it can't carry both.
            None => return Err("--user is required when stdin isn't a terminal".to_string()),
        };
        let password = prompt::password("Password: ")?;

        let resp = http_client(HeaderMap::new())
            .post(format!("{base}/auth/login"))
            .json(&LoginRequest { username, password })
            .send()
            .await
            .map_err(|e| format!("request failed: {e}"))?;

        if resp.status() == StatusCode::UNAUTHORIZED {
            return Err("login failed: invalid username or password".to_string());
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
            client: http_client(headers),
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
