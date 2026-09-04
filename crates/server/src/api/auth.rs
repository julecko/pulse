//! Login / logout and the [`Session`] extractor that gates every other route.
//!
//! Login verifies a username/password against the `users` table (Argon2), then
//! mints a 256-bit opaque token. Only `sha256(token)` is stored in `sessions`;
//! the raw token is shown to the client once. Requests carry it as
//! `Authorization: Bearer <token>` (the SSE endpoint also accepts `?token=`).

use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;

use axum::Json;
use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ApiState;
use super::dto::ApiError;
use crate::password;
use crate::store::now_unix_ms;

/// Proof of a valid session. A route that takes this as an argument is
/// authenticated.
pub struct Session {
    #[allow(dead_code)]
    pub user: String,
    pub token_hash: String,
}

impl FromRequestParts<ApiState> for Session {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts).ok_or_else(ApiError::unauthorized)?;
        let token_hash = sha256_hex(token.as_bytes());
        match state
            .store
            .session_user(token_hash.clone(), now_unix_ms())
            .await?
        {
            Some(user) => Ok(Session { user, token_hash }),
            None => Err(ApiError::unauthorized_msg("invalid or expired session")),
        }
    }
}

#[derive(Deserialize)]
pub struct LoginReq {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub struct LoginResp {
    token: String,
    expires_at_ms: u64,
}

pub async fn login(
    State(st): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginReq>,
) -> Result<Json<LoginResp>, ApiError> {
    // Brute-force / DoS guard: throttle attempts per client address *before* any
    // password hashing, then cap how many Argon2 verifications run at once
    // (Argon2id is deliberately expensive in CPU and memory).
    let ip = client_ip(&st, &headers, peer);
    if !st.login_rate.allow(ip) {
        tracing::warn!(%ip, user = %req.username, "login rate limit hit");
        return Err(ApiError::too_many_requests(
            "too many login attempts — try again in a minute",
        ));
    }
    let _permit = st.login_gate.clone().acquire_owned().await.ok();

    let stored = st.store.user_hash(req.username.clone()).await?;
    let password = req.password.clone();
    // Run Argon2 on the blocking pool — inline it would stall an async worker.
    // Always verify (against a dummy hash when the user is missing) so timing
    // doesn't reveal whether the account exists.
    let ok = tokio::task::spawn_blocking(move || match &stored {
        Some(hash) => password::verify(&password, hash),
        None => {
            password::verify(&password, dummy_hash());
            false
        }
    })
    .await
    .map_err(ApiError::internal)?;

    if !ok {
        tracing::warn!(%ip, user = %req.username, "failed login");
        return Err(ApiError::unauthorized_msg("invalid username or password"));
    }

    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(ApiError::internal)?;
    let token = hex(&raw);
    let now = now_unix_ms();
    let expires_at_ms = now.saturating_add(st.session_ttl_secs.saturating_mul(1000));
    st.store
        .create_session(
            sha256_hex(token.as_bytes()),
            req.username,
            now,
            expires_at_ms,
        )
        .await?;

    Ok(Json(LoginResp {
        token,
        expires_at_ms,
    }))
}

pub async fn logout(session: Session, State(st): State<ApiState>) -> Result<StatusCode, ApiError> {
    st.store.delete_session(session.token_hash).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `Authorization: Bearer <t>` header, or `?token=<t>` in the query string
/// (needed for `EventSource`, which can't set headers).
fn bearer_token(parts: &Parts) -> Option<String> {
    if let Some(value) = parts.headers.get(AUTHORIZATION)
        && let Ok(s) = value.to_str()
        && let Some(rest) = s.strip_prefix("Bearer ")
    {
        let t = rest.trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    parts.uri.query().and_then(|q| {
        q.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            (k == "token" && !v.is_empty()).then(|| v.to_string())
        })
    })
}

/// Client address for the login limiter. When `trust_forwarded_for` is set (the
/// API is behind a reverse proxy on loopback), the first `X-Forwarded-For` entry
/// wins; otherwise the raw socket peer.
fn client_ip(st: &ApiState, headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    if st.trust_forwarded_for
        && let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return ip;
    }
    peer.ip()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A real Argon2 hash used only to spend verification time when the account
/// doesn't exist.
fn dummy_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| password::hash("Dm9!qLz2@xR7wYp1").expect("dummy hash"))
}
