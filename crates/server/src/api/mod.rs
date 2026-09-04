//! HTTP API for the pulse app: live host state + queryable history, behind
//! username/password sessions.
//!
//! Runs in-process on its own listener (`[api] bind`). Plaintext — put a
//! TLS-terminating reverse proxy in front for remote access.

mod auth;
mod downsample;
mod dto;
mod routes;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::info;

use crate::config::Api;
use crate::limits::RateLimiter;
use crate::live::Live;
use crate::store::StoreHandle;

/// Upper bound for `session_ttl_secs` (~10 years) — keeps expiry arithmetic well
/// clear of `u64` overflow and rejects nonsensical config.
const MAX_SESSION_TTL_SECS: u64 = 10 * 365 * 24 * 3600;

#[derive(Clone)]
struct ApiState {
    store: StoreHandle,
    live: Arc<Live>,
    session_ttl_secs: u64,
    online_secs: u64,
    /// Per-client-address throttle on `POST /login`.
    login_rate: Arc<RateLimiter>,
    /// Bounds how many Argon2 verifications run concurrently.
    login_gate: Arc<Semaphore>,
    trust_forwarded_for: bool,
}

/// Bind `cfg.bind`. Split from [`serve`] so the daemon can fail fast on a bad or
/// occupied API port instead of only logging it from a background task.
pub async fn bind(cfg: &Api) -> io::Result<TcpListener> {
    let listener = TcpListener::bind(&cfg.bind).await?;
    info!(bind = %cfg.bind, "API listening");
    Ok(listener)
}

/// Serve the API on `listener` until the process exits.
pub async fn serve(
    listener: TcpListener,
    cfg: Api,
    store: StoreHandle,
    live: Arc<Live>,
) -> io::Result<()> {
    let login_gate = Arc::new(Semaphore::new(match cfg.login_max_concurrent {
        0 => Semaphore::MAX_PERMITS,
        n => n,
    }));
    let state = ApiState {
        store,
        live,
        session_ttl_secs: cfg.session_ttl_secs.clamp(60, MAX_SESSION_TTL_SECS),
        online_secs: cfg.online_secs,
        login_rate: Arc::new(RateLimiter::new(cfg.login_per_ip_per_minute)),
        login_gate,
        trust_forwarded_for: cfg.trust_forwarded_for,
    };
    axum::serve(
        listener,
        routes::router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}
