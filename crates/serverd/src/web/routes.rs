//! Route definitions. Add new routes here and wire them into [`router`].
//!
//! Routes are split by who may call them:
//! - `public`: no authentication; only what's needed before anyone can
//!   authenticate (health check, user login, agent pairing). Login and
//!   pairing are rate-limited per client IP (see [`rate_limit`]).
//! - `agent`: require a valid agent bearer token (see [`auth::require_agent`])
//! - `user`: require a logged-in user's session token (see
//!   [`auth::require_user`]); everything `pulse-server-cli` manages

use axum::middleware;
use axum::routing::{MethodRouter, delete, get, post};
use axum::{Extension, Router};
use sqlx::SqlitePool;

use super::rate_limit::{self, RateLimitConfig, RateLimiter};
use super::{agents, auth, auth_events, metrics, users};

pub fn router(pool: SqlitePool, session_ttl_hours: u32, limits: &RateLimitConfig) -> Router {
    let public = Router::new()
        .route("/healthz", get(healthz))
        .route(
            "/auth/login",
            rate_limited(
                post(users::login).layer(Extension(users::SessionTtl(session_ttl_hours))),
                RateLimiter::failures_only("login", limits.login_failures_per_minute),
            ),
        )
        .route(
            "/agents/pair",
            rate_limited(
                post(agents::pair),
                RateLimiter::new("pair", limits.pair_per_minute),
            ),
        );

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
        .route(
            "/agents/pairing",
            get(agents::get_pairing).put(agents::set_pairing),
        )
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

/// `route` behind `limiter`, or unchanged if that limit is disabled.
fn rate_limited(
    route: MethodRouter<SqlitePool>,
    limiter: Option<std::sync::Arc<RateLimiter>>,
) -> MethodRouter<SqlitePool> {
    match limiter {
        Some(limiter) => route.layer(middleware::from_fn_with_state(limiter, rate_limit::enforce)),
        None => route,
    }
}

async fn healthz() -> &'static str {
    "ok"
}
