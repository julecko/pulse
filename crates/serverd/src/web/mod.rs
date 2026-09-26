mod agents;
mod auth;
mod auth_events;
mod metrics;
mod rate_limit;
mod routes;
mod users;

use std::net::SocketAddr;
use std::path::PathBuf;

use axum_server::tls_rustls::RustlsConfig;
use pulse_shared::tls::TlsConfig;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebConfig {
    pub bind: SocketAddr,
    pub tls: TlsConfig,
    /// How long a user session from `POST /auth/login` stays valid.
    pub session_ttl_hours: u32,
    pub rate_limit: rate_limit::RateLimitConfig,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([0, 0, 0, 0], 8443)),
            tls: TlsConfig::default(),
            session_ttl_hours: 24 * 7,
            rate_limit: rate_limit::RateLimitConfig::default(),
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

pub async fn serve(cfg: &WebConfig, pool: SqlitePool) -> Result<(), WebError> {
    let cert = cfg.tls.resolved_cert();
    let key = cfg.tls.resolved_key();

    let tls = RustlsConfig::from_pem_file(&cert, &key)
        .await
        .map_err(|e| WebError::Tls(cert.clone(), key.clone(), e))?;

    tracing::info!(bind = %cfg.bind, cert = %cert.display(), key = %key.display(), "web server listening");

    axum_server::bind_rustls(cfg.bind, tls)
        .serve(
            routes::router(pool, cfg.session_ttl_hours, &cfg.rate_limit)
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .map_err(|e| WebError::Serve(cfg.bind, e))
}
