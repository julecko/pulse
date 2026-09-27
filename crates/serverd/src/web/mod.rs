mod agents;
mod alert_rules;
mod alerts;
mod auth;
mod auth_events;
mod conn_limit;
mod geo_alerts;
mod metrics;
mod notify;
mod offline;
mod pam_notifications;
mod push_devices;
mod rate_limit;
mod retention;
mod routes;
mod users;

pub(crate) use rate_limit::RateLimiter;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use pulse_shared::tls::TlsConfig;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tower_http::timeout::TimeoutLayer;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebConfig {
    pub bind: SocketAddr,
    pub tls: TlsConfig,
    /// How long a user session from `POST /auth/login` stays valid.
    pub session_ttl_hours: u32,
    pub rate_limit: rate_limit::RateLimitConfig,
    pub connections: conn_limit::ConnectionLimits,
}

/// Longest a client may take to send a request's headers (including the
/// wait for the next request on a kept-alive connection); stops clients
/// that trickle headers to hold connections open.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest a whole request may take once its headers are in, body and
/// handler included (a login can wait for a free password check); `408`
/// after that.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([0, 0, 0, 0], 8443)),
            tls: TlsConfig::default(),
            session_ttl_hours: 24 * 7,
            rate_limit: rate_limit::RateLimitConfig::default(),
            connections: conn_limit::ConnectionLimits::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WebError {
    #[error("loading TLS cert {0} / key {1}: {2}")]
    Tls(PathBuf, PathBuf, std::io::Error),
    #[error("serving on {0}: {1}")]
    Serve(SocketAddr, std::io::Error),
}

pub async fn serve(
    cfg: &WebConfig,
    pool: SqlitePool,
    alerting: Arc<crate::alerting::Alerting>,
    retention: Arc<crate::db::retention::Retention>,
) -> Result<(), WebError> {
    let cert = cfg.tls.resolved_cert();
    let key = cfg.tls.resolved_key();

    let tls = RustlsConfig::from_pem_file(&cert, &key)
        .await
        .map_err(|e| WebError::Tls(cert.clone(), key.clone(), e))?;

    let tls = http1_only_alpn(&tls);

    tracing::info!(bind = %cfg.bind, cert = %cert.display(), key = %key.display(), "web server listening");

    let acceptor = RustlsAcceptor::new(tls)
        .acceptor(conn_limit::ConnLimitAcceptor::new(cfg.connections.clone()));
    let mut server = axum_server::bind(cfg.bind).acceptor(acceptor);
    // HTTP/1.1 only: the agent and CLI don't speak HTTP/2, and hyper has no
    // header read timeout for it. Without a timer hyper ignores the timeout.
    let builder = server.http_builder();
    *builder = std::mem::replace(builder, Builder::new(TokioExecutor::new())).http1_only();
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);

    let router = routes::router(
        pool,
        cfg.session_ttl_hours,
        &cfg.rate_limit,
        alerting,
        retention,
    )
    .layer(TimeoutLayer::with_status_code(
        StatusCode::REQUEST_TIMEOUT,
        REQUEST_TIMEOUT,
    ));
    server
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .map_err(|e| WebError::Serve(cfg.bind, e))
}

/// For unexpected failures (database errors, ...): logs `err` and returns a
/// `500`. Release builds send only a generic message, so internals like SQL
/// or file paths never reach a client; debug builds send `err` itself, to
/// make development easier.
pub(super) fn internal_error(err: impl std::fmt::Display) -> (StatusCode, String) {
    tracing::error!(%err, "internal error");
    let body = if cfg!(debug_assertions) {
        format!("internal server error: {err}")
    } else {
        "internal server error".to_string()
    };
    (StatusCode::INTERNAL_SERVER_ERROR, body)
}

/// `tls` advertising only `http/1.1` in ALPN, so clients that would pick
/// HTTP/2 (e.g. curl) fall back to HTTP/1.1 instead of failing.
fn http1_only_alpn(tls: &RustlsConfig) -> RustlsConfig {
    let mut config = (*tls.get_inner()).clone();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    RustlsConfig::from_config(Arc::new(config))
}
