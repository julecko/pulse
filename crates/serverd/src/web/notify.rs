//! Plain push notifications sent by `pulse-agent-cli notify` on an agent's
//! host: pushed to every registered device (see [`crate::push`]) and not
//! stored anywhere.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use protocol::Notification;
use sqlx::SqlitePool;

use super::auth::AuthedAgent;
use super::rate_limit::RateLimiter;
use crate::alerting::Alerting;
use crate::push::PushMessage;

/// Pushes per agent (see
/// [`super::rate_limit::RateLimitConfig::notifications_per_agent_per_minute`]),
/// shared by this route and pushed PAM events (see
/// [`super::auth_events`]); `None` when disabled.
#[derive(Clone)]
pub struct NotifyLimiter(pub Option<Arc<RateLimiter<i64>>>);

/// Pushes the notification in the background. `202` with how many devices
/// it's going to; `503` if push isn't configured. The title is always the
/// agent's hostname (plus the given title, if any), so a notification
/// can't pass itself off as another host's.
pub async fn send(
    State(pool): State<SqlitePool>,
    Extension(agent): Extension<AuthedAgent>,
    Extension(alerting): Extension<Arc<Alerting>>,
    Json(req): Json<Notification>,
) -> Result<(StatusCode, String), (StatusCode, String)> {
    req.validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err))?;

    let push = alerting.push();
    if !push.is_enabled() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "push notifications aren't configured on the server ([push] fcm_service_account)"
                .to_string(),
        ));
    }

    let hostname: String = sqlx::query_scalar("SELECT hostname FROM agents WHERE id = ?")
        .bind(agent.id)
        .fetch_one(&pool)
        .await
        .map_err(super::internal_error)?;
    let devices: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM push_devices")
        .fetch_one(&pool)
        .await
        .map_err(super::internal_error)?;

    let title = match req.title.as_deref().map(str::trim) {
        Some(title) => format!("{hostname}: {title}"),
        None => hostname,
    };
    push.notify_all(
        &pool,
        PushMessage::plain(
            title,
            req.message,
            format!("notification from agent {}", agent.id),
        ),
    );
    tracing::info!(agent_id = agent.id, devices, "notification sent");

    Ok((
        StatusCode::ACCEPTED,
        format!("sending to {devices} device(s)"),
    ))
}
