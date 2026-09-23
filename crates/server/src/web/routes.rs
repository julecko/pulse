//! Route definitions. Add new routes here and wire them into [`router`].

use axum::Router;
use axum::routing::{delete, get, post};
use sqlx::SqlitePool;

use super::agents;

pub fn router(pool: SqlitePool) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/agents/pair", post(agents::pair))
        .route("/agents", get(agents::list))
        .route("/agents/{id}/approve", post(agents::approve))
        .route("/agents/{id}/revoke", post(agents::revoke))
        .route("/agents/{id}", delete(agents::remove))
        .route("/agents/me", get(agents::me))
        .with_state(pool)
}

async fn healthz() -> &'static str {
    "ok"
}
