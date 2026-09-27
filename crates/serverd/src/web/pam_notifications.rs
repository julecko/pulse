//! Per-agent PAM push settings: which kinds of PAM event the server pushes
//! to every registered device when an agent reports one (see
//! [`super::auth_events`]). Nothing is pushed by default; events are stored
//! either way.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use protocol::{AuthEventKind, PamNotifications, SetPamNotifications};
use sqlx::SqlitePool;

use super::auth::AuthedUser;

fn not_found() -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, "agent not found".to_string())
}

/// Every agent's settings, by agent ID.
pub async fn list(
    State(pool): State<SqlitePool>,
) -> Result<Json<Vec<PamNotifications>>, (StatusCode, String)> {
    let agents: Vec<(i64, String)> = sqlx::query_as("SELECT id, hostname FROM agents ORDER BY id")
        .fetch_all(&pool)
        .await
        .map_err(super::internal_error)?;
    let rows: Vec<(i64, String)> =
        sqlx::query_as("SELECT agent_id, kind FROM agent_pam_notifications")
            .fetch_all(&pool)
            .await
            .map_err(super::internal_error)?;

    Ok(Json(
        agents
            .into_iter()
            .map(|(agent_id, hostname)| PamNotifications {
                agent_id,
                hostname,
                kinds: kinds_of(agent_id, &rows),
            })
            .collect(),
    ))
}

pub async fn get(
    State(pool): State<SqlitePool>,
    Path(id): Path<i64>,
) -> Result<Json<PamNotifications>, (StatusCode, String)> {
    load(&pool, id).await.map(Json)
}

/// Replaces which of the agent's PAM events are pushed; an empty list turns
/// them off.
pub async fn set(
    State(pool): State<SqlitePool>,
    Extension(user): Extension<AuthedUser>,
    Path(id): Path<i64>,
    Json(req): Json<SetPamNotifications>,
) -> Result<Json<PamNotifications>, (StatusCode, String)> {
    let mut tx = pool.begin().await.map_err(super::internal_error)?;
    let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM agents WHERE id = ?")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(super::internal_error)?;
    if exists.is_none() {
        return Err(not_found());
    }

    sqlx::query("DELETE FROM agent_pam_notifications WHERE agent_id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(super::internal_error)?;
    for kind in &req.kinds {
        sqlx::query(
            "INSERT INTO agent_pam_notifications (agent_id, kind) VALUES (?, ?)
             ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(kind.as_str())
        .execute(&mut *tx)
        .await
        .map_err(super::internal_error)?;
    }
    tx.commit().await.map_err(super::internal_error)?;

    let settings = load(&pool, id).await?;
    let kinds: Vec<_> = settings.kinds.iter().map(|k| k.as_str()).collect();
    tracing::info!(agent_id = id, kinds = %kinds.join(","), by = %user.username, "PAM push settings changed");
    Ok(Json(settings))
}

async fn load(pool: &SqlitePool, id: i64) -> Result<PamNotifications, (StatusCode, String)> {
    let hostname: Option<String> = sqlx::query_scalar("SELECT hostname FROM agents WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(super::internal_error)?;
    let hostname = hostname.ok_or_else(not_found)?;
    let rows: Vec<(i64, String)> =
        sqlx::query_as("SELECT agent_id, kind FROM agent_pam_notifications WHERE agent_id = ?")
            .bind(id)
            .fetch_all(pool)
            .await
            .map_err(super::internal_error)?;
    Ok(PamNotifications {
        agent_id: id,
        hostname,
        kinds: kinds_of(id, &rows),
    })
}

/// `agent_id`'s kinds from `(agent_id, kind)` rows, in a fixed order.
/// Unknown kinds can't be stored (the table's CHECK), so none are dropped.
fn kinds_of(agent_id: i64, rows: &[(i64, String)]) -> Vec<AuthEventKind> {
    AuthEventKind::ALL
        .into_iter()
        .filter(|kind| {
            rows.iter()
                .any(|(id, k)| *id == agent_id && k == kind.as_str())
        })
        .collect()
}
