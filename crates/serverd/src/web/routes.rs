//! Route definitions. Add new routes here and wire them into [`router`].
//!
//! Routes are split by who may call them:
//! - `public`: no authentication; only what's needed before anyone can
//!   authenticate (health check, user login, agent pairing). Login and
//!   pairing are rate-limited per client IP (see [`rate_limit`]), and
//!   logins also per username (see [`users::login`]).
//! - `agent`: require a valid agent bearer token (see [`auth::require_agent`])
//! - `user`: require a logged-in user's session token (see
//!   [`auth::require_user`]); everything `pulse-server-cli` manages

use axum::extract::DefaultBodyLimit;
use axum::middleware;
use std::sync::Arc;

use axum::routing::{MethodRouter, delete, get, patch, post, put};
use axum::{Extension, Router};
use sqlx::SqlitePool;

use super::rate_limit::{self, RateLimitConfig, RateLimiter};
use super::{
    agents, alert_rules, alerts, auth, auth_events, geo_alerts, metrics, notify, pam_notifications,
    push_devices, retention, users,
};
use crate::alerting::Alerting;
use crate::db::retention::Retention;

/// Largest request body accepted on any route (axum's default is 2 MiB).
/// A metrics snapshot is ~1 KiB for a typical host and ~30 KiB for one with
/// hundreds of cores and disks; everything else is far smaller.
const MAX_BODY_BYTES: usize = 64 * 1024;

pub fn router(
    pool: SqlitePool,
    session_ttl_hours: u32,
    limits: &RateLimitConfig,
    alerting: Arc<Alerting>,
    retention: Arc<Retention>,
) -> Router {
    let public = Router::new()
        .route("/healthz", get(healthz))
        .route(
            "/auth/login",
            rate_limited(
                post(users::login),
                RateLimiter::failures_only("login", limits.login_failures_per_minute),
            ),
        )
        .layer(Extension(users::SessionTtl(session_ttl_hours)))
        .layer(Extension(users::UserLoginLimiter(
            RateLimiter::failures_only("login_user", limits.login_failures_per_user_per_minute),
        )))
        .route(
            "/agents/pair",
            rate_limited(
                post(agents::pair),
                RateLimiter::new("pair", limits.pair_per_minute),
            ),
        );

    // One budget per agent for everything it pushes: `notify` and PAM
    // events its push settings pick.
    let notify_limiter = RateLimiter::new("notify", limits.notifications_per_agent_per_minute);
    let agent = Router::new()
        .route("/agents/me", get(agents::me))
        .route(
            "/agents/me/auth-events",
            per_agent(
                post(auth_events::ingest),
                RateLimiter::new("auth_events", limits.auth_events_per_agent_per_minute),
            ),
        )
        .route(
            "/agents/me/metrics",
            per_agent(
                post(metrics::ingest),
                RateLimiter::new("metrics", limits.metrics_per_agent_per_minute),
            ),
        )
        .route(
            "/agents/me/notify",
            per_agent(post(notify::send), notify_limiter.clone()),
        )
        .layer(Extension(notify::NotifyLimiter(notify_limiter)))
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
        .route("/agents/{id}/unrevoke", post(agents::unrevoke))
        .route("/agents/{id}", delete(agents::remove))
        .route("/agents/{id}/auth-events", get(auth_events::list))
        .route("/agents/pam-notifications", get(pam_notifications::list))
        .route(
            "/agents/{id}/pam-notifications",
            get(pam_notifications::get).put(pam_notifications::set),
        )
        .route("/agents/{id}/metrics", get(metrics::list))
        .route(
            "/alert-rules",
            get(alert_rules::list).post(alert_rules::create),
        )
        .route(
            "/alert-rules/{id}",
            patch(alert_rules::update).delete(alert_rules::remove),
        )
        .route("/alerts", get(alerts::list))
        .route(
            "/geo-alerts/settings",
            get(geo_alerts::get).put(geo_alerts::set),
        )
        .route("/alerts/{id}/acknowledge", post(alerts::acknowledge))
        .route(
            "/push-devices",
            get(push_devices::list).post(push_devices::register),
        )
        .route("/push-devices/{id}", delete(push_devices::remove))
        .route("/retention", get(retention::list))
        .route("/retention/{data}", put(retention::set))
        .route_layer(middleware::from_fn_with_state(
            pool.clone(),
            auth::require_user,
        ));

    Router::new()
        .merge(public)
        .merge(agent)
        .merge(user)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(Extension(alerting))
        .layer(Extension(retention))
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

/// `route` limited per calling agent (see [`rate_limit::enforce_per_agent`]),
/// or unchanged if that limit is disabled. The agent routes' `route_layer`
/// runs [`auth::require_agent`] before this.
fn per_agent(
    route: MethodRouter<SqlitePool>,
    limiter: Option<std::sync::Arc<RateLimiter<i64>>>,
) -> MethodRouter<SqlitePool> {
    match limiter {
        Some(limiter) => route.layer(middleware::from_fn_with_state(
            limiter,
            rate_limit::enforce_per_agent,
        )),
        None => route,
    }
}

async fn healthz() -> &'static str {
    "ok"
}
