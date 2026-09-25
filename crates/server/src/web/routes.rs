//! Route definitions. Add new routes here and wire them into [`router`].
//!
//! Routes are split by who may call them:
//! - `public`: no authentication
//! - `agent`: require a valid agent bearer token (see [`auth::require_agent`])

use axum::Router;
use axum::middleware;
use axum::routing::{delete, get, post};
use sqlx::SqlitePool;

use super::{agents, auth};

pub fn router(pool: SqlitePool) -> Router {
    let public = Router::new()
        .route("/healthz", get(healthz))
        .route("/agents/pair", post(agents::pair))
        .route("/agents", get(agents::list))
        .route("/agents/{id}/approve", post(agents::approve))
        .route("/agents/{id}/revoke", post(agents::revoke))
        .route("/agents/{id}", delete(agents::remove));

    let agent = Router::new()
        .route("/agents/me", get(agents::me))
        .route_layer(middleware::from_fn_with_state(
            pool.clone(),
            auth::require_agent,
        ));

    Router::new().merge(public).merge(agent).with_state(pool)
}

async fn healthz() -> &'static str {
    "ok"
}
