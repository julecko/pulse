//! PAM auth events (sessions, failed auth) forwarded by agents.

use std::borrow::Cow;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use protocol::{AuthEvent, AuthEventRecord};
use sqlx::SqlitePool;

use super::auth::AuthedAgent;

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

/// Stores one event for the calling agent. Behind
/// [`super::auth::require_agent`], so `agent_id` always comes from the token.
pub async fn ingest(
    State(pool): State<SqlitePool>,
    Extension(agent): Extension<AuthedAgent>,
    Json(event): Json<AuthEvent>,
) -> Result<StatusCode, (StatusCode, String)> {
    sqlx::query(
        "INSERT INTO auth_events (agent_id, kind, service, user, ruser, rhost, tty, occurred_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, datetime(?, 'unixepoch'))",
    )
    .bind(agent.id)
    .bind(event.kind.as_str())
    .bind(truncate(&event.service))
    .bind(truncate(&event.user))
    .bind(event.ruser.as_deref().map(truncate))
    .bind(event.rhost.as_deref().map(truncate))
    .bind(event.tty.as_deref().map(truncate))
    .bind(event.occurred_at)
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::debug!(
        agent_id = agent.id,
        kind = event.kind.as_str(),
        "stored auth event"
    );

    Ok(StatusCode::NO_CONTENT)
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
        }
    }
}

/// Most recent events for one agent, newest first.
pub async fn list(
    State(pool): State<SqlitePool>,
    Path(id): Path<i64>,
) -> Result<Json<Vec<AuthEventRecord>>, (StatusCode, String)> {
    let rows: Vec<AuthEventRow> = sqlx::query_as(
        "SELECT id, kind, service, user, ruser, rhost, tty, occurred_at FROM auth_events
         WHERE agent_id = ? ORDER BY occurred_at DESC, id DESC LIMIT ?",
    )
    .bind(id)
    .bind(LIST_LIMIT)
    .fetch_all(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

#[cfg(test)]
mod tests {
    use super::*;

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
