//! PAM auth events (sessions, failed auth) forwarded by agents.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use protocol::{AuthEvent, AuthEventRecord};
use sqlx::SqlitePool;

use super::auth::AuthedAgent;

/// Rows returned by [`list`].
const LIST_LIMIT: i64 = 100;

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
    .bind(&event.service)
    .bind(&event.user)
    .bind(&event.ruser)
    .bind(&event.rhost)
    .bind(&event.tty)
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
