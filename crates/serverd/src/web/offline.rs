//! Per-agent offline alert settings: after how long without metrics an
//! approved agent counts as offline (see [`crate::offline`]).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use protocol::{
    MAX_OFFLINE_AFTER_SECS, MIN_OFFLINE_AFTER_SECS, OfflineAlertSetting, SetOfflineAlert,
};
use sqlx::SqlitePool;

use super::auth::AuthedUser;

#[derive(sqlx::FromRow)]
struct Row {
    id: i64,
    hostname: String,
    status: String,
    offline_after_secs: Option<i64>,
    last_metrics_at: Option<String>,
    offline: bool,
}

impl From<Row> for OfflineAlertSetting {
    fn from(row: Row) -> Self {
        OfflineAlertSetting {
            agent_id: row.id,
            hostname: row.hostname,
            status: row.status,
            // The table's CHECK keeps it in range.
            after_secs: row.offline_after_secs.and_then(|s| u32::try_from(s).ok()),
            last_metrics_at: row.last_metrics_at,
            offline: row.offline,
        }
    }
}

const SELECT: &str = "SELECT a.id, a.hostname, a.status, a.offline_after_secs, a.last_metrics_at,
        EXISTS (SELECT 1 FROM alerts al JOIN offline_alerts o ON o.alert_id = al.id
                WHERE al.agent_id = a.id AND al.resolved_at IS NULL) AS offline
     FROM agents a";

/// Every agent's setting and state.
pub async fn list(
    State(pool): State<SqlitePool>,
) -> Result<Json<Vec<OfflineAlertSetting>>, (StatusCode, String)> {
    let rows: Vec<Row> = sqlx::query_as(&format!("{SELECT} ORDER BY a.id"))
        .fetch_all(&pool)
        .await
        .map_err(super::internal_error)?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

/// Sets (or, with `after_secs: null`, turns off) agent `id`'s limit.
/// Turning it off resolves an active offline alert.
pub async fn set(
    State(pool): State<SqlitePool>,
    Extension(user): Extension<AuthedUser>,
    Path(id): Path<i64>,
    Json(req): Json<SetOfflineAlert>,
) -> Result<Json<OfflineAlertSetting>, (StatusCode, String)> {
    if let Some(secs) = req.after_secs
        && !(MIN_OFFLINE_AFTER_SECS..=MAX_OFFLINE_AFTER_SECS).contains(&secs)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "after_secs must be {MIN_OFFLINE_AFTER_SECS}-{MAX_OFFLINE_AFTER_SECS} (1 minute to 30 days)"
            ),
        ));
    }

    let result = sqlx::query(
        "UPDATE agents SET offline_after_secs = ?,
             offline_after_set_at = CASE WHEN ? IS NULL THEN NULL ELSE datetime('now') END
         WHERE id = ?",
    )
    .bind(req.after_secs)
    .bind(req.after_secs)
    .bind(id)
    .execute(&pool)
    .await
    .map_err(super::internal_error)?;
    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "agent not found".to_string()));
    }
    if req.after_secs.is_none() {
        crate::offline::resolve(&pool, id)
            .await
            .map_err(super::internal_error)?;
    }
    tracing::info!(agent_id = id, after_secs = ?req.after_secs, by = %user.username, "offline alert setting changed");

    let row: Row = sqlx::query_as(&format!("{SELECT} WHERE a.id = ?"))
        .bind(id)
        .fetch_one(&pool)
        .await
        .map_err(super::internal_error)?;
    Ok(Json(row.into()))
}
