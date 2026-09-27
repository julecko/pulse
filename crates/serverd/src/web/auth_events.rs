//! PAM auth events (sessions, failed auth) forwarded by agents, and pushed
//! to every registered device for the kinds the agent's PAM push settings
//! pick (see [`super::pam_notifications`]). SSH logins are also checked for
//! geo alerts (see [`crate::geo_alerts`]).

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use protocol::{AuthEvent, AuthEventKind, AuthEventRecord};
use sqlx::SqlitePool;

use super::auth::AuthedAgent;
use super::notify::NotifyLimiter;
use super::rate_limit::RateLimiter;
use crate::alerting::Alerting;
use crate::push::PushMessage;

/// Rows returned by [`list`].
const LIST_LIMIT: i64 = 100;

/// Longest stored text field. Longer values (e.g. an absurd username in a
/// failed SSH login) are truncated rather than rejected, so an attacker
/// can't keep their attempts out of the record by making them oversized.
const MAX_FIELD_LEN: usize = 256;

/// `s` cut to at most [`MAX_FIELD_LEN`] bytes, on a char boundary, with a
/// trailing `…` when cut.
fn truncate(s: &str) -> Cow<'_, str> {
    if s.len() <= MAX_FIELD_LEN {
        return Cow::Borrowed(s);
    }
    let mut end = MAX_FIELD_LEN - '…'.len_utf8();
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    Cow::Owned(format!("{}…", &s[..end]))
}

/// Longest user or host name shown in a push. They can come from an
/// attacker (the username typed at a failed SSH login), so they're also
/// escaped (see [`protocol::escape_for_display`]).
const MAX_PUSH_FIELD_CHARS: usize = 64;

/// Stores one event for the calling agent, then pushes it if the agent's
/// settings ask for that kind (see [`push_event`]). Behind
/// [`super::auth::require_agent`], so `agent_id` always comes from the token.
pub async fn ingest(
    State(pool): State<SqlitePool>,
    Extension(agent): Extension<AuthedAgent>,
    Extension(alerting): Extension<Arc<Alerting>>,
    Extension(NotifyLimiter(limiter)): Extension<NotifyLimiter>,
    Json(event): Json<AuthEvent>,
) -> Result<StatusCode, (StatusCode, String)> {
    let located = alerting.geo().locate(event.rhost.as_deref());
    let location = located.as_ref().map(|(_, location)| location);

    sqlx::query(
        "INSERT INTO auth_events (agent_id, kind, service, user, ruser, rhost, tty, occurred_at,
                                  country_code, country_name, city)
         VALUES (?, ?, ?, ?, ?, ?, ?, datetime(?, 'unixepoch'), ?, ?, ?)",
    )
    .bind(agent.id)
    .bind(event.kind.as_str())
    .bind(truncate(&event.service))
    .bind(truncate(&event.user))
    .bind(event.ruser.as_deref().map(truncate))
    .bind(event.rhost.as_deref().map(truncate))
    .bind(event.tty.as_deref().map(truncate))
    .bind(event.occurred_at)
    .bind(location.and_then(|l| l.country_code.as_deref()))
    .bind(location.and_then(|l| l.country_name.as_deref()))
    .bind(location.and_then(|l| l.city.as_deref()))
    .execute(&pool)
    .await
    .map_err(super::internal_error)?;

    tracing::debug!(
        agent_id = agent.id,
        kind = event.kind.as_str(),
        "stored auth event"
    );

    push_event(&pool, &alerting, limiter.as_deref(), agent.id, &event).await;
    alerting
        .geo()
        .evaluate(
            &pool,
            alerting.push(),
            limiter.as_deref(),
            agent.id,
            &event,
            located.as_ref(),
        )
        .await;

    Ok(StatusCode::NO_CONTENT)
}

/// Pushes a stored event if the agent's settings pick its kind, push is
/// configured, and the agent is within its push budget (shared with
/// `POST /agents/me/notify`). Never fails the ingest: the event is stored
/// either way.
async fn push_event(
    pool: &SqlitePool,
    alerting: &Alerting,
    limiter: Option<&RateLimiter<i64>>,
    agent_id: i64,
    event: &AuthEvent,
) {
    if !alerting.push().is_enabled() {
        return;
    }
    let hostname: Option<String> = match sqlx::query_scalar(
        "SELECT a.hostname FROM agents a
         JOIN agent_pam_notifications n ON n.agent_id = a.id
         WHERE a.id = ? AND n.kind = ?",
    )
    .bind(agent_id)
    .bind(event.kind.as_str())
    .fetch_optional(pool)
    .await
    {
        Ok(hostname) => hostname,
        Err(err) => {
            tracing::warn!(%err, agent_id, "PAM event not pushed: loading push settings failed");
            return;
        }
    };
    // Not a kind this agent pushes.
    let Some(hostname) = hostname else {
        return;
    };
    if let Some(limiter) = limiter
        && limiter.check(agent_id, Instant::now()).is_err()
    {
        tracing::warn!(
            agent_id,
            "PAM event not pushed: agent over its push limit (event stored)"
        );
        return;
    }

    let (title, body) = push_text(&hostname, event);
    alerting.push().notify_all(
        pool,
        PushMessage::plain(title, body, format!("PAM event from agent {agent_id}")),
    );
}

/// `s` escaped and cut to [`MAX_PUSH_FIELD_CHARS`], for a push.
fn push_field(s: &str) -> String {
    let escaped = protocol::escape_for_display(s);
    if escaped.chars().count() <= MAX_PUSH_FIELD_CHARS {
        return escaped.into_owned();
    }
    let mut cut: String = escaped.chars().take(MAX_PUSH_FIELD_CHARS - 1).collect();
    cut.push('…');
    cut
}

/// Title and body of the push for `event`, e.g. "web01: sshd login" /
/// "root from 192.0.2.7".
fn push_text(hostname: &str, event: &AuthEvent) -> (String, String) {
    let service = push_field(&event.service);
    let title = match event.kind {
        AuthEventKind::SessionOpen => format!("{hostname}: {service} login"),
        AuthEventKind::SessionClose => format!("{hostname}: {service} logout"),
        AuthEventKind::AuthFailure => format!("{hostname}: failed {service} login"),
    };

    let mut body = push_field(&event.user);
    if let Some(ruser) = event
        .ruser
        .as_deref()
        .filter(|r| !r.is_empty() && *r != event.user)
    {
        body.push_str(&format!(" (by {})", push_field(ruser)));
    }
    if let Some(rhost) = event.rhost.as_deref().filter(|h| !h.is_empty()) {
        body.push_str(&format!(" from {}", push_field(rhost)));
    }
    (title, body)
}

#[derive(sqlx::FromRow)]
struct AuthEventRow {
    id: i64,
    kind: String,
    service: String,
    user: String,
    ruser: Option<String>,
    rhost: Option<String>,
    tty: Option<String>,
    occurred_at: String,
    country_code: Option<String>,
    country_name: Option<String>,
    city: Option<String>,
}

impl From<AuthEventRow> for AuthEventRecord {
    fn from(row: AuthEventRow) -> Self {
        AuthEventRecord {
            id: row.id,
            kind: row.kind,
            service: row.service,
            user: row.user,
            ruser: row.ruser,
            rhost: row.rhost,
            tty: row.tty,
            occurred_at: row.occurred_at,
            country_code: row.country_code,
            country_name: row.country_name,
            city: row.city,
        }
    }
}

/// Most recent events for one agent, newest first.
pub async fn list(
    State(pool): State<SqlitePool>,
    Path(id): Path<i64>,
) -> Result<Json<Vec<AuthEventRecord>>, (StatusCode, String)> {
    let rows: Vec<AuthEventRow> = sqlx::query_as(
        "SELECT id, kind, service, user, ruser, rhost, tty, occurred_at,
                country_code, country_name, city
         FROM auth_events
         WHERE agent_id = ? ORDER BY occurred_at DESC, id DESC LIMIT ?",
    )
    .bind(id)
    .bind(LIST_LIMIT)
    .fetch_all(&pool)
    .await
    .map_err(super::internal_error)?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: AuthEventKind, service: &str, user: &str, ruser: Option<&str>) -> AuthEvent {
        AuthEvent {
            kind,
            service: service.to_string(),
            user: user.to_string(),
            ruser: ruser.map(str::to_string),
            rhost: (service == "sshd").then(|| "192.0.2.7".to_string()),
            tty: None,
            occurred_at: 0,
        }
    }

    #[test]
    fn push_text_per_kind() {
        let login = event(AuthEventKind::SessionOpen, "sshd", "root", None);
        assert_eq!(
            push_text("web01", &login),
            ("web01: sshd login".into(), "root from 192.0.2.7".into())
        );
        let sudo = event(AuthEventKind::SessionOpen, "sudo", "root", Some("alice"));
        assert_eq!(
            push_text("web01", &sudo),
            ("web01: sudo login".into(), "root (by alice)".into())
        );
        let logout = event(AuthEventKind::SessionClose, "sshd", "root", None);
        assert_eq!(push_text("web01", &logout).0, "web01: sshd logout");
        let failed = event(AuthEventKind::AuthFailure, "sshd", "admin", None);
        assert_eq!(push_text("web01", &failed).0, "web01: failed sshd login");
    }

    #[test]
    fn push_text_escapes_and_shortens_attacker_input() {
        let user = format!("\x1b[2J{}", "a".repeat(100));
        let (_, body) = push_text(
            "web01",
            &event(AuthEventKind::AuthFailure, "su", &user, None),
        );
        assert!(!body.contains('\x1b'));
        assert!(body.starts_with("\\x1b[2J"));
        assert_eq!(body.chars().count(), MAX_PUSH_FIELD_CHARS);
        assert!(body.ends_with('…'));
    }

    #[test]
    fn truncates_long_fields_on_a_char_boundary() {
        assert_eq!(truncate("root"), "root");
        let long = "ž".repeat(200); // 400 bytes
        let cut = truncate(&long);
        assert!(cut.len() <= MAX_FIELD_LEN);
        assert!(cut.ends_with('…'));
        assert!(cut.starts_with("žž"));
    }
}
