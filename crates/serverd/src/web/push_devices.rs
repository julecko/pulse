//! Devices alert pushes go to (see [`crate::push`]). The mobile app
//! registers its FCM token as the logged-in user; every user's devices get
//! every pushed alert.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use protocol::{PushDevice, PushPlatform, RegisterPushDevice};
use sqlx::SqlitePool;

use super::auth::AuthedUser;

/// FCM tokens are ~150-200 characters; allow plenty of room.
const MAX_TOKEN_LEN: usize = 4096;
const MAX_NAME_LEN: usize = 100;
/// Per user, so a stolen session can't register tokens without end.
const MAX_DEVICES_PER_USER: i64 = 20;

#[derive(sqlx::FromRow)]
struct DeviceRow {
    id: i64,
    username: String,
    platform: String,
    name: Option<String>,
    created_at: String,
    last_seen_at: String,
}

impl TryFrom<DeviceRow> for PushDevice {
    type Error = String;

    fn try_from(row: DeviceRow) -> Result<Self, String> {
        Ok(PushDevice {
            id: row.id,
            username: row.username,
            platform: row.platform.parse::<PushPlatform>()?,
            name: row.name,
            created_at: row.created_at,
            last_seen_at: row.last_seen_at,
        })
    }
}

const DEVICE_SELECT: &str =
    "SELECT d.id, u.username, d.platform, d.name, d.created_at, d.last_seen_at
                             FROM push_devices d JOIN users u ON u.id = d.user_id";

fn bad_request(msg: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, msg.into())
}

/// Every user's devices.
pub async fn list(
    State(pool): State<SqlitePool>,
) -> Result<Json<Vec<PushDevice>>, (StatusCode, String)> {
    let rows: Vec<DeviceRow> = sqlx::query_as(&format!("{DEVICE_SELECT} ORDER BY d.id"))
        .fetch_all(&pool)
        .await
        .map_err(super::internal_error)?;

    rows.into_iter()
        .map(PushDevice::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map(Json)
        .map_err(super::internal_error)
}

/// Registers the caller's device, or refreshes it if the token is known
/// (then it moves to the caller, e.g. after logging in as someone else).
pub async fn register(
    State(pool): State<SqlitePool>,
    Extension(user): Extension<AuthedUser>,
    Json(req): Json<RegisterPushDevice>,
) -> Result<Json<PushDevice>, (StatusCode, String)> {
    if req.token.is_empty()
        || req.token.len() > MAX_TOKEN_LEN
        || !req.token.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(bad_request(format!(
            "token must be 1-{MAX_TOKEN_LEN} printable ASCII characters"
        )));
    }
    let name = req.name.as_deref().map(str::trim).filter(|n| !n.is_empty());
    if let Some(name) = name
        && (name.chars().count() > MAX_NAME_LEN
            || name.chars().any(protocol::is_unsafe_display_char))
    {
        return Err(bad_request(format!(
            "name must be at most {MAX_NAME_LEN} characters, without control characters"
        )));
    }

    let others: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM push_devices WHERE user_id = ? AND token != ?")
            .bind(user.id)
            .bind(&req.token)
            .fetch_one(&pool)
            .await
            .map_err(super::internal_error)?;
    if others >= MAX_DEVICES_PER_USER {
        return Err((
            StatusCode::CONFLICT,
            format!("at most {MAX_DEVICES_PER_USER} devices per user; remove some first"),
        ));
    }

    let id: i64 = sqlx::query_scalar(
        "INSERT INTO push_devices (user_id, token, platform, name) VALUES (?, ?, ?, ?)
         ON CONFLICT (token) DO UPDATE SET
             user_id = excluded.user_id, platform = excluded.platform,
             name = excluded.name, last_seen_at = datetime('now')
         RETURNING id",
    )
    .bind(user.id)
    .bind(&req.token)
    .bind(req.platform.as_str())
    .bind(name)
    .fetch_one(&pool)
    .await
    .map_err(super::internal_error)?;

    let row: DeviceRow = sqlx::query_as(&format!("{DEVICE_SELECT} WHERE d.id = ?"))
        .bind(id)
        .fetch_one(&pool)
        .await
        .map_err(super::internal_error)?;

    tracing::info!(device_id = id, by = %user.username, "push device registered");
    PushDevice::try_from(row)
        .map(Json)
        .map_err(super::internal_error)
}

pub async fn remove(
    State(pool): State<SqlitePool>,
    Extension(user): Extension<AuthedUser>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    let result = sqlx::query("DELETE FROM push_devices WHERE id = ?")
        .bind(id)
        .execute(&pool)
        .await
        .map_err(super::internal_error)?;

    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "device not found".to_string()));
    }

    tracing::info!(device_id = id, by = %user.username, "push device removed");
    Ok(StatusCode::NO_CONTENT)
}
