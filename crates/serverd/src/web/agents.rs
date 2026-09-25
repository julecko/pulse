//! Agent pairing: registration/polling, manual approval, revocation, and an
//! example route protected by [`super::auth::require_agent`].

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use protocol::{AgentSummary, ApproveResponse, PairRequest, PairResponse};
use sqlx::SqlitePool;
use uuid::Uuid;

use super::auth::{AuthedAgent, AuthedUser};

#[derive(sqlx::FromRow)]
struct AgentRow {
    id: i64,
    status: String,
    token: Option<String>,
}

/// Registers a new fingerprint (status starts `pending`) or, for a known
/// fingerprint, reports its current status — `approved` responses include
/// the bearer token every time (see [`super::auth`] for why).
pub async fn pair(
    State(pool): State<SqlitePool>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<PairRequest>,
) -> Result<Json<PairResponse>, (StatusCode, String)> {
    let public_ip = peer.ip().to_string();

    let existing: Option<AgentRow> =
        sqlx::query_as("SELECT id, status, token FROM agents WHERE fingerprint = ?")
            .bind(&req.fingerprint)
            .fetch_optional(&pool)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let row = match existing {
        Some(row) => {
            sqlx::query(
                "UPDATE agents SET hostname = ?, public_ip = ?, os_name = ?, os_version = ?, kernel_version = ?, arch = ? WHERE id = ?",
            )
            .bind(&req.hostname)
            .bind(&public_ip)
            .bind(&req.os_name)
            .bind(&req.os_version)
            .bind(&req.kernel_version)
            .bind(&req.arch)
            .bind(row.id)
            .execute(&pool)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            row
        }
        None => {
            sqlx::query(
                "INSERT INTO agents (fingerprint, hostname, public_ip, os_name, os_version, kernel_version, arch, status)
                 VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')",
            )
            .bind(&req.fingerprint)
            .bind(&req.hostname)
            .bind(&public_ip)
            .bind(&req.os_name)
            .bind(&req.os_version)
            .bind(&req.kernel_version)
            .bind(&req.arch)
            .execute(&pool)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            AgentRow {
                id: 0,
                status: "pending".to_string(),
                token: None,
            }
        }
    };

    let response = match row.status.as_str() {
        "approved" => PairResponse::Approved {
            token: row.token.unwrap_or_default(),
        },
        "revoked" => PairResponse::Revoked,
        _ => PairResponse::Pending,
    };

    Ok(Json(response))
}

#[derive(sqlx::FromRow)]
struct AgentSummaryRow {
    id: i64,
    fingerprint: String,
    hostname: String,
    status: String,
    created_at: String,
}

impl From<AgentSummaryRow> for AgentSummary {
    fn from(row: AgentSummaryRow) -> Self {
        AgentSummary {
            id: row.id,
            fingerprint: row.fingerprint,
            hostname: row.hostname,
            status: row.status,
            created_at: row.created_at,
        }
    }
}

/// Lists every agent, pending included — this is the "join requests" view.
pub async fn list(
    State(pool): State<SqlitePool>,
) -> Result<Json<Vec<AgentSummary>>, (StatusCode, String)> {
    let rows: Vec<AgentSummaryRow> = sqlx::query_as(
        "SELECT id, fingerprint, hostname, status, created_at FROM agents ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

pub async fn approve(
    State(pool): State<SqlitePool>,
    Extension(user): Extension<AuthedUser>,
    Path(id): Path<i64>,
) -> Result<Json<ApproveResponse>, (StatusCode, String)> {
    let token = Uuid::new_v4().simple().to_string();

    let result = sqlx::query("UPDATE agents SET status = 'approved', token = ? WHERE id = ?")
        .bind(&token)
        .bind(id)
        .execute(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "agent not found".to_string()));
    }

    tracing::info!(agent_id = id, by = %user.username, "agent approved");

    Ok(Json(ApproveResponse { token }))
}

pub async fn revoke(
    State(pool): State<SqlitePool>,
    Extension(user): Extension<AuthedUser>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    let result = sqlx::query("UPDATE agents SET status = 'revoked', token = NULL WHERE id = ?")
        .bind(id)
        .execute(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "agent not found".to_string()));
    }

    tracing::info!(agent_id = id, by = %user.username, "agent revoked");

    Ok(StatusCode::NO_CONTENT)
}

/// Deletes an agent entirely (not just revokes it) — since its fingerprint
/// is then gone from the table, a re-pair with the same (or a new)
/// fingerprint starts over as a fresh `pending` request. Cascades to its
/// `root_notifications`/`metrics` rows via the FK constraints.
pub async fn remove(
    State(pool): State<SqlitePool>,
    Extension(user): Extension<AuthedUser>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    let result = sqlx::query("DELETE FROM agents WHERE id = ?")
        .bind(id)
        .execute(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "agent not found".to_string()));
    }

    tracing::info!(agent_id = id, by = %user.username, "agent removed");

    Ok(StatusCode::NO_CONTENT)
}

/// Example protected route: proves [`super::auth::require_agent`] works end-to-end by
/// returning the calling agent's own row.
pub async fn me(
    State(pool): State<SqlitePool>,
    Extension(agent): Extension<AuthedAgent>,
) -> Result<Json<AgentSummary>, (StatusCode, String)> {
    let row: AgentSummaryRow = sqlx::query_as(
        "SELECT id, fingerprint, hostname, status, created_at FROM agents WHERE id = ?",
    )
    .bind(agent.id)
    .fetch_one(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(row.into()))
}
