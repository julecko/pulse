//! Alerts fired by rules (see [`crate::alerting`]): listing and
//! acknowledging. They're created and resolved by the server only.

use std::str::FromStr;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use protocol::{AlertRecord, AlertSeverity};
use serde::Deserialize;
use sqlx::SqlitePool;

use super::auth::AuthedUser;

const DEFAULT_LIST_LIMIT: i64 = 50;
const MAX_LIST_LIMIT: i64 = 1000;

#[derive(sqlx::FromRow)]
struct AlertRow {
    id: i64,
    rule_id: Option<i64>,
    agent_id: Option<i64>,
    hostname: Option<String>,
    severity: String,
    title: String,
    message: String,
    triggered_at: String,
    resolved_at: Option<String>,
    acknowledged_at: Option<String>,
    acknowledged_by: Option<String>,
}

impl TryFrom<AlertRow> for AlertRecord {
    type Error = String;

    fn try_from(row: AlertRow) -> Result<Self, String> {
        Ok(AlertRecord {
            id: row.id,
            rule_id: row.rule_id,
            agent_id: row.agent_id,
            hostname: row.hostname,
            severity: AlertSeverity::from_str(&row.severity)?,
            title: row.title,
            message: row.message,
            triggered_at: row.triggered_at,
            resolved_at: row.resolved_at,
            acknowledged_at: row.acknowledged_at,
            acknowledged_by: row.acknowledged_by,
        })
    }
}

#[derive(Deserialize)]
pub struct ListQuery {
    /// Only alerts about this agent.
    agent_id: Option<i64>,
    /// Only alerts that haven't resolved yet.
    #[serde(default)]
    active: bool,
    limit: Option<i64>,
}

/// Most recent alerts, newest first. `?agent_id=`, `?active=true`,
/// `?limit=` (default 50, at most 1000).
pub async fn list(
    State(pool): State<SqlitePool>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<AlertRecord>>, (StatusCode, String)> {
    let limit = query
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);

    let rows: Vec<AlertRow> = sqlx::query_as(
        "SELECT a.id, a.rule_id, a.agent_id, g.hostname, a.severity, a.title, a.message,
                a.triggered_at, a.resolved_at, a.acknowledged_at, a.acknowledged_by
         FROM alerts a LEFT JOIN agents g ON g.id = a.agent_id
         WHERE (?1 IS NULL OR a.agent_id = ?1) AND (?2 = 0 OR a.resolved_at IS NULL)
         ORDER BY a.id DESC LIMIT ?3",
    )
    .bind(query.agent_id)
    .bind(query.active)
    .bind(limit)
    .fetch_all(&pool)
    .await
    .map_err(super::internal_error)?;

    rows.into_iter()
        .map(AlertRecord::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map(Json)
        .map_err(super::internal_error)
}

/// Marks an alert as seen. Acknowledging it again keeps the first
/// acknowledgement.
pub async fn acknowledge(
    State(pool): State<SqlitePool>,
    Extension(user): Extension<AuthedUser>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    let result = sqlx::query(
        "UPDATE alerts SET acknowledged_at = datetime('now'), acknowledged_by = ?
         WHERE id = ? AND acknowledged_at IS NULL",
    )
    .bind(&user.username)
    .bind(id)
    .execute(&pool)
    .await
    .map_err(super::internal_error)?;

    if result.rows_affected() == 0 {
        let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM alerts WHERE id = ?")
            .bind(id)
            .fetch_optional(&pool)
            .await
            .map_err(super::internal_error)?;
        if exists.is_none() {
            return Err((StatusCode::NOT_FOUND, "alert not found".to_string()));
        }
    } else {
        tracing::info!(alert_id = id, by = %user.username, "alert acknowledged");
    }
    Ok(StatusCode::NO_CONTENT)
}
