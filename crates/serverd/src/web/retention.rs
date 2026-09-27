//! Retention periods: list them, override one, or reset it to the server
//! config's default (see [`crate::db::retention`]).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use protocol::{MAX_RETENTION_DAYS, RetentionData, RetentionSetting, SetRetention};
use sqlx::SqlitePool;

use super::auth::AuthedUser;
use crate::db::retention::Retention;

pub async fn list(
    State(pool): State<SqlitePool>,
    Extension(retention): Extension<Arc<Retention>>,
) -> Result<Json<Vec<RetentionSetting>>, (StatusCode, String)> {
    retention
        .settings(&pool)
        .await
        .map(Json)
        .map_err(super::internal_error)
}

/// Sets `data`'s retention period, or (`days: null`) resets it to the
/// config default. Lowering it deletes older rows right away.
pub async fn set(
    State(pool): State<SqlitePool>,
    Extension(retention): Extension<Arc<Retention>>,
    Extension(user): Extension<AuthedUser>,
    Path(data): Path<String>,
    Json(req): Json<SetRetention>,
) -> Result<Json<RetentionSetting>, (StatusCode, String)> {
    let data: RetentionData = data.parse().map_err(|e| (StatusCode::NOT_FOUND, e))?;

    match req.days {
        Some(days) if days > MAX_RETENTION_DAYS => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("days must be 0-{MAX_RETENTION_DAYS} (0 = keep forever)"),
            ));
        }
        Some(days) => {
            sqlx::query(
                "INSERT INTO retention_settings (data, days, updated_by) VALUES (?, ?, ?)
                 ON CONFLICT (data) DO UPDATE SET
                     days = excluded.days, updated_by = excluded.updated_by,
                     updated_at = datetime('now')",
            )
            .bind(data.as_str())
            .bind(days)
            .bind(&user.username)
            .execute(&pool)
            .await
            .map_err(super::internal_error)?;
            tracing::warn!(%data, days, by = %user.username, "retention changed");
        }
        None => {
            sqlx::query("DELETE FROM retention_settings WHERE data = ?")
                .bind(data.as_str())
                .execute(&pool)
                .await
                .map_err(super::internal_error)?;
            tracing::warn!(
                %data,
                days = retention.default_days(data),
                by = %user.username,
                "retention reset to config default"
            );
        }
    }
    retention.changed();

    let settings = retention
        .settings(&pool)
        .await
        .map_err(super::internal_error)?;
    settings
        .into_iter()
        .find(|s| s.data == data)
        .map(Json)
        .ok_or_else(|| super::internal_error("retention setting missing"))
}
