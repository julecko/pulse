//! Route definitions. Add new routes here and wire them into [`router`].
//!
//! Routes are split by who may call them:
//! - `public`: no authentication; only what's needed before anyone can
//!   authenticate (health check, user login, agent pairing)
//! - `agent`: require a valid agent bearer token (see [`auth::require_agent`])
//! - `user`: require a logged-in user's session token (see
//!   [`auth::require_user`]); everything `pulse-server-cli` manages

use axum::middleware;
use axum::routing::{delete, get, post};
use axum::{Extension, Router};
use sqlx::SqlitePool;

use super::{agents, auth, auth_events, metrics, users};

pub fn router(pool: SqlitePool, session_ttl_hours: u32) -> Router {
    let public = Router::new()
        .route("/healthz", get(healthz))
        .route(
            "/auth/login",
            post(users::login).layer(Extension(users::SessionTtl(session_ttl_hours))),
        )
        .route("/agents/pair", post(agents::pair));

    let agent = Router::new()
        .route("/agents/me", get(agents::me))
        .route("/agents/me/auth-events", post(auth_events::ingest))
        .route("/agents/me/metrics", post(metrics::ingest))
        .route_layer(middleware::from_fn_with_state(
            pool.clone(),
            auth::require_agent,
        ));

    let user = Router::new()
        .route("/users/me", get(users::me))
        .route("/auth/logout", post(users::logout))
        .route("/agents", get(agents::list))
        .route("/agents/{id}/approve", post(agents::approve))
        .route("/agents/{id}/revoke", post(agents::revoke))
        .route("/agents/{id}", delete(agents::remove))
        .route("/agents/{id}/auth-events", get(auth_events::list))
        .route("/agents/{id}/metrics", get(metrics::list))
        .route_layer(middleware::from_fn_with_state(
            pool.clone(),
            auth::require_user,
        ));

    Router::new()
        .merge(public)
        .merge(agent)
        .merge(user)
        .with_state(pool)
}

async fn healthz() -> &'static str {
    "ok"
}
