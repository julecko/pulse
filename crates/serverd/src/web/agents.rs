//! Agent pairing: registration/polling, manual approval, revocation, the
//! pairing open/closed switch, and an example route protected by
//! [`super::auth::require_agent`].

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use protocol::{AgentSummary, PairRequest, PairResponse, PairingStatus, SetPairingRequest};
use sqlx::SqlitePool;

use super::auth::{AuthedAgent, AuthedUser};
use crate::credentials;

/// Longest accepted fingerprint (new agents send 32 hex chars, agents
/// paired before secrets existed a 36-char UUID).
const MAX_FINGERPRINT_LEN: usize = 64;
/// Longest accepted host info field (hostname, OS name, ...).
const MAX_HOST_FIELD_LEN: usize = 255;
/// New pairing requests are refused while this many are already pending,
/// so an open pairing window can't be flooded.
const MAX_PENDING_AGENTS: i64 = 100;
/// Longest `minutes` for `PUT /agents/pairing` (one week).
const MAX_PAIRING_WINDOW_MINUTES: u32 = 7 * 24 * 60;

const PAIRING_CLOSED: &str = "pairing is closed: this server isn't accepting new agents (a user can open it with `pulse-server-cli agents pairing open`)";

#[derive(sqlx::FromRow)]
struct AgentRow {
    id: i64,
    status: String,
    secret_hash: Option<String>,
}

/// Registers a new agent (status starts `pending`) or, for a known
/// fingerprint, reports its current status. Never returns a credential:
/// the agent's own secret becomes its bearer token once approved.
///
/// - Known fingerprint: the secret must match the one it registered with,
///   otherwise `401`, so knowing a fingerprint (which is public: logs,
///   `GET /agents`) is worth nothing.
/// - New fingerprint: only while pairing is open (see [`set_pairing`]) and
///   fewer than [`MAX_PENDING_AGENTS`] are pending, and the fingerprint must
///   be [`protocol::agent_fingerprint`] of the secret, so nobody can
///   register a fingerprint that isn't theirs.
///
/// Known agents can poll while pairing is closed, so approved ones keep
/// noticing revocation.
pub async fn pair(
    State(pool): State<SqlitePool>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<PairRequest>,
) -> Result<Json<PairResponse>, (StatusCode, String)> {
    validate_pair_request(&req)?;
    let public_ip = peer.ip().to_string();
    let secret_hash = credentials::hash_token(&req.secret);

    let existing: Option<AgentRow> =
        sqlx::query_as("SELECT id, status, secret_hash FROM agents WHERE fingerprint = ?")
            .bind(&req.fingerprint)
            .fetch_optional(&pool)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let status = match existing {
        Some(row) => {
            if row.secret_hash.as_deref() != Some(secret_hash.as_str()) {
                tracing::warn!(peer = %peer.ip(), agent_id = row.id, "pairing poll with wrong secret");
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "wrong secret for this fingerprint".to_string(),
                ));
            }

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
            .map_err(db_error)?;
            row.status
        }
        None => {
            if !pairing_open(&pool).await? {
                tracing::debug!(peer = %peer.ip(), hostname = %req.hostname, "rejected pairing request: pairing closed");
                return Err((StatusCode::FORBIDDEN, PAIRING_CLOSED.to_string()));
            }

            if !protocol::is_valid_agent_secret(&req.secret)
                || req.fingerprint != protocol::agent_fingerprint(&req.secret)
            {
                tracing::warn!(peer = %peer.ip(), hostname = %req.hostname, "rejected pairing request: fingerprint doesn't match secret");
                return Err((
                    StatusCode::BAD_REQUEST,
                    "fingerprint doesn't match the secret".to_string(),
                ));
            }

            let pending: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM agents WHERE status = 'pending'")
                    .fetch_one(&pool)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            if pending >= MAX_PENDING_AGENTS {
                tracing::warn!(peer = %peer.ip(), pending, "rejected pairing request: too many pending");
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!(
                        "too many pending pairing requests ({pending}); approve or remove some first"
                    ),
                ));
            }

            sqlx::query(
                "INSERT INTO agents (fingerprint, secret_hash, hostname, public_ip, os_name, os_version, kernel_version, arch, status)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')",
            )
            .bind(&req.fingerprint)
            .bind(&secret_hash)
            .bind(&req.hostname)
            .bind(&public_ip)
            .bind(&req.os_name)
            .bind(&req.os_version)
            .bind(&req.kernel_version)
            .bind(&req.arch)
            .execute(&pool)
            .await
            .map_err(db_error)?;

            tracing::info!(peer = %peer.ip(), hostname = %req.hostname, fingerprint = %req.fingerprint, "new pairing request");
            "pending".to_string()
        }
    };

    Ok(Json(match status.as_str() {
        "approved" => PairResponse::Approved,
        "revoked" => PairResponse::Revoked,
        _ => PairResponse::Pending,
    }))
}

fn validate_pair_request(req: &PairRequest) -> Result<(), (StatusCode, String)> {
    // New agents send AGENT_SECRET_LEN chars (checked on registration);
    // agents paired before secrets existed use their old 32-char token.
    let secret_ok = (32..=protocol::AGENT_SECRET_LEN).contains(&req.secret.len())
        && req
            .secret
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !secret_ok {
        return Err((
            StatusCode::BAD_REQUEST,
            "secret must be lowercase hex".to_string(),
        ));
    }
    if req.fingerprint.is_empty() || req.fingerprint.len() > MAX_FINGERPRINT_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("fingerprint must be 1-{MAX_FINGERPRINT_LEN} bytes"),
        ));
    }
    for (name, value) in [
        ("hostname", &req.hostname),
        ("os_name", &req.os_name),
        ("os_version", &req.os_version),
        ("kernel_version", &req.kernel_version),
        ("arch", &req.arch),
    ] {
        if value.is_empty() || value.len() > MAX_HOST_FIELD_LEN {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("{name} must be 1-{MAX_HOST_FIELD_LEN} bytes"),
            ));
        }
    }
    Ok(())
}

/// The only unique columns an agent row gets are its fingerprint and secret
/// hash (hostnames may repeat), so a violation means two requests raced to
/// register the same agent; the loser gets `409` rather than a raw database
/// error, and its next poll finds the row.
fn db_error(e: sqlx::Error) -> (StatusCode, String) {
    match e {
        sqlx::Error::Database(db) if db.is_unique_violation() => (
            StatusCode::CONFLICT,
            "this agent is already registered".to_string(),
        ),
        e => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn pairing_open(pool: &SqlitePool) -> Result<bool, (StatusCode, String)> {
    sqlx::query_scalar(
        "SELECT open = 1 AND (open_until IS NULL OR open_until > datetime('now'))
         FROM pairing_state WHERE id = 1",
    )
    .fetch_optional(pool)
    .await
    .map(|open| open.unwrap_or(false))
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn pairing_status(pool: &SqlitePool) -> Result<PairingStatus, (StatusCode, String)> {
    let (open, open_until, updated_by, updated_at): (bool, Option<String>, Option<String>, String) =
        sqlx::query_as(
            "SELECT open = 1 AND (open_until IS NULL OR open_until > datetime('now')),
                    open_until, updated_by, updated_at
             FROM pairing_state WHERE id = 1",
        )
        .fetch_one(pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(PairingStatus {
        open,
        open_until: open.then_some(open_until).flatten(),
        updated_by,
        updated_at,
    })
}

/// Whether new agents can pair right now.
pub async fn get_pairing(
    State(pool): State<SqlitePool>,
) -> Result<Json<PairingStatus>, (StatusCode, String)> {
    Ok(Json(pairing_status(&pool).await?))
}

/// Opens (optionally for `minutes`, then it closes by itself) or closes
/// pairing for new agents.
pub async fn set_pairing(
    State(pool): State<SqlitePool>,
    Extension(user): Extension<AuthedUser>,
    Json(req): Json<SetPairingRequest>,
) -> Result<Json<PairingStatus>, (StatusCode, String)> {
    let open_until_offset = match (req.open, req.minutes) {
        (true, Some(minutes)) if (1..=MAX_PAIRING_WINDOW_MINUTES).contains(&minutes) => {
            Some(format!("+{minutes} minutes"))
        }
        (true, Some(_)) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("minutes must be 1-{MAX_PAIRING_WINDOW_MINUTES}"),
            ));
        }
        _ => None,
    };

    sqlx::query(
        "UPDATE pairing_state
         SET open = ?, open_until = datetime('now', ?), updated_by = ?, updated_at = datetime('now')
         WHERE id = 1",
    )
    .bind(req.open)
    // datetime('now', NULL) is NULL: no end time.
    .bind(open_until_offset)
    .bind(&user.username)
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let status = pairing_status(&pool).await?;
    tracing::info!(
        open = status.open,
        open_until = ?status.open_until,
        by = %user.username,
        "pairing {}",
        if status.open { "opened" } else { "closed" }
    );
    Ok(Json(status))
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

/// Approves a pending agent: from then on its own secret is accepted as
/// its bearer token. Nothing is issued or returned. Revoked agents can't be
/// approved again, since their secret may be compromised: remove them and
/// have the host pair again with a new identity.
pub async fn approve(
    State(pool): State<SqlitePool>,
    Extension(user): Extension<AuthedUser>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    let status: Option<String> = sqlx::query_scalar("SELECT status FROM agents WHERE id = ?")
        .bind(id)
        .fetch_optional(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match status.as_deref() {
        None => return Err((StatusCode::NOT_FOUND, "agent not found".to_string())),
        Some("revoked") => {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "agent {id} is revoked and can't be approved again (its secret may be compromised): \
                     remove it with `agents remove {id}`, run `pulse-agentd reset-identity` on its host, \
                     then approve the new pairing request"
                ),
            ));
        }
        Some(_) => {}
    }

    sqlx::query("UPDATE agents SET status = 'approved' WHERE id = ?")
        .bind(id)
        .execute(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::info!(agent_id = id, by = %user.username, "agent approved");

    Ok(StatusCode::NO_CONTENT)
}

/// Stops accepting the agent's secret. Its `secret_hash` stays, so the agent
/// can still authenticate its pairing polls and learn it's been revoked.
pub async fn revoke(
    State(pool): State<SqlitePool>,
    Extension(user): Extension<AuthedUser>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    let result = sqlx::query("UPDATE agents SET status = 'revoked' WHERE id = ?")
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
