mod agents;
mod auth;
mod auth_events;
mod routes;
mod users;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use axum_server::tls_rustls::RustlsConfig;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

/// Release default cert dir; matches `ConfigurationDirectory=pulse` in the systemd unit.
pub const DEFAULT_CERT_DIR: &str = "/etc/pulse/certs";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebConfig {
    pub bind: SocketAddr,
    pub tls: TlsConfig,
    /// How long a user session from `POST /auth/login` stays valid.
    pub session_ttl_hours: u32,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([0, 0, 0, 0], 8443)),
            tls: TlsConfig::default(),
            session_ttl_hours: 24 * 7,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    /// Explicit cert file. Unset: `<cert dir>/cert.pem`.
    pub cert: Option<PathBuf>,
    /// Explicit key file. Unset: `<cert dir>/key.pem`.
    pub key: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum WebError {
    #[error("loading TLS cert {0} / key {1}: {2}")]
    Tls(PathBuf, PathBuf, std::io::Error),
    #[error("serving on {0}: {1}")]
    Serve(SocketAddr, std::io::Error),
}

fn cert_dir() -> PathBuf {
    if cfg!(debug_assertions) {
        Path::new("certs").to_path_buf()
    } else {
        PathBuf::from(DEFAULT_CERT_DIR)
    }
}

pub async fn serve(cfg: &WebConfig, pool: SqlitePool) -> Result<(), WebError> {
    let dir = cert_dir();
    let cert = cfg.tls.cert.clone().unwrap_or_else(|| dir.join("cert.pem"));
    let key = cfg.tls.key.clone().unwrap_or_else(|| dir.join("key.pem"));

    let tls = RustlsConfig::from_pem_file(&cert, &key)
        .await
        .map_err(|e| WebError::Tls(cert.clone(), key.clone(), e))?;

    tracing::info!(bind = %cfg.bind, cert = %cert.display(), key = %key.display(), "web server listening");

    axum_server::bind_rustls(cfg.bind, tls)
        .serve(
            routes::router(pool, cfg.session_ttl_hours)
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .map_err(|e| WebError::Serve(cfg.bind, e))
}
