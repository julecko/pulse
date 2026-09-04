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
use std::sync::Arc;

use tracing::info;

use crate::config::Api;
use crate::live::Live;
use crate::store::StoreHandle;

#[derive(Clone)]
struct ApiState {
    store: StoreHandle,
    live: Arc<Live>,
    session_ttl_secs: u64,
    online_secs: u64,
}

/// Bind `cfg.bind` and serve the API until the process exits. Returns on a bind
/// error (the caller logs and continues — the ingest listener is independent).
pub async fn serve(cfg: Api, store: StoreHandle, live: Arc<Live>) -> io::Result<()> {
    let state = ApiState {
        store,
        live,
        session_ttl_secs: cfg.session_ttl_secs.max(60),
        online_secs: cfg.online_secs,
    };
    let listener = tokio::net::TcpListener::bind(&cfg.bind).await?;
    info!(bind = %cfg.bind, "API listening");
    axum::serve(listener, routes::router(state)).await
}
