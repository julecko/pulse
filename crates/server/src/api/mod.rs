//! HTTP API for the pulse app: live host state + queryable history, behind
//! username/password sessions.
//!
//! Runs in-process on its own listener (`[api] bind`). Serve it over HTTPS with
//! `[api] tls = true`, or leave it plaintext behind a TLS-terminating proxy.

mod auth;
mod downsample;
mod dto;
mod routes;

use std::io;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio_rustls::rustls::ServerConfig;
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

/// Bind `cfg.bind`. Split from [`serve`] (and kept sync) so a bad/occupied API
/// port fails the daemon at startup instead of only logging from a spawned task.
pub fn bind(cfg: &Api) -> io::Result<TcpListener> {
    let listener = TcpListener::bind(&cfg.bind)?;
    listener.set_nonblocking(true)?;
    info!(bind = %cfg.bind, tls = cfg.tls, "API listening");
    Ok(listener)
}

/// Resolve and load the API listener's TLS config, or `None` when
/// `[api] tls = false`. Called at startup so a missing/bad cert fails fast.
pub fn load_tls(cfg: &Api) -> io::Result<Option<Arc<ServerConfig>>> {
    if !cfg.tls {
        return Ok(None);
    }
    let (cert, key) = tls_paths(cfg);
    let config = pulse_config::tls::api_server_config(&cert, &key).map_err(io::Error::other)?;
    Ok(Some(config))
}

fn tls_paths(cfg: &Api) -> (PathBuf, PathBuf) {
    let dir = pulse_config::tls_dir("server");
    let pick = |configured: &str, default: &str| {
        if configured.is_empty() {
            dir.join(default)
        } else {
            PathBuf::from(configured)
        }
    };
    (
        pick(&cfg.tls_cert, "api.crt"),
        pick(&cfg.tls_key, "api.key"),
    )
}

/// Serve the API on `listener` until the process exits. `tls` from [`load_tls`].
pub async fn serve(
    listener: TcpListener,
    tls: Option<Arc<ServerConfig>>,
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
    let make = routes::router(state).into_make_service_with_connect_info::<SocketAddr>();

    match tls {
        Some(config) => {
            let acceptor = axum_server::tls_rustls::RustlsConfig::from_config(config);
            axum_server::from_tcp_rustls(listener, acceptor)?
                .serve(make)
                .await
        }
        None => axum_server::from_tcp(listener)?.serve(make).await,
    }
}
