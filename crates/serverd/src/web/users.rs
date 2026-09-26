//! User login/logout and an example route protected by
//! [`super::auth::require_user`]. There's deliberately no registration
//! route: users are created with `pulse-server-cli users add`, which writes to
//! the database directly.

use std::sync::LazyLock;

use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use protocol::{LoginRequest, LoginResponse, UserInfo};
use sqlx::SqlitePool;

use super::auth::AuthedUser;
use crate::credentials;

/// How long a session from [`login`] stays valid; from `[web] session_ttl_hours`.
#[derive(Clone, Copy)]
pub struct SessionTtl(pub u32);

const INVALID_CREDENTIALS: &str = "invalid username or password";

/// Password checks allowed at once. Each argon2 verify holds ~19 MiB for
/// its duration, so without a cap a flood of logins (even rate-limited per
/// IP, from many IPs) could exhaust memory; excess logins wait their turn.
static PASSWORD_CHECKS: LazyLock<tokio::sync::Semaphore> = LazyLock::new(|| {
    let cpus = std::thread::available_parallelism().map_or(2, |n| n.get());
    tokio::sync::Semaphore::new(cpus.clamp(2, 8))
});

pub async fn login(
    State(pool): State<SqlitePool>,
    Extension(SessionTtl(ttl_hours)): Extension<SessionTtl>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let user: Option<(i64, String)> =
        sqlx::query_as("SELECT id, password_hash FROM users WHERE username = ?")
            .bind(&req.username)
            .fetch_optional(&pool)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Always run a full verify, even for unknown users, so response time
    // doesn't reveal which usernames exist.
    let (user_id, hash) = match user {
        Some((id, hash)) => (Some(id), hash),
        None => (None, credentials::DUMMY_PASSWORD_HASH.clone()),
    };
    let password = req.password;
    let permit = PASSWORD_CHECKS
        .acquire()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // argon2 is deliberately slow; keep it off the async worker threads.
    let valid = tokio::task::spawn_blocking(move || credentials::verify_password(&password, &hash))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    drop(permit);

    let Some(user_id) = user_id.filter(|_| valid) else {
        tracing::warn!(username = %req.username, "failed login");
        return Err((StatusCode::UNAUTHORIZED, INVALID_CREDENTIALS.to_string()));
    };

    let token = credentials::new_session_token();
    let expires_at: String = sqlx::query_scalar(
        "INSERT INTO user_sessions (user_id, token_hash, expires_at)
         VALUES (?, ?, datetime('now', ?)) RETURNING expires_at",
    )
    .bind(user_id)
    .bind(credentials::hash_token(&token))
    .bind(format!("+{ttl_hours} hours"))
    .fetch_one(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::info!(username = %req.username, "user logged in");

    Ok(Json(LoginResponse { token, expires_at }))
}

/// Ends the session the request authenticated with; other sessions of the
/// same user stay valid.
pub async fn logout(
    State(pool): State<SqlitePool>,
    Extension(user): Extension<AuthedUser>,
) -> Result<StatusCode, (StatusCode, String)> {
    sqlx::query("DELETE FROM user_sessions WHERE id = ?")
        .bind(user.session_id)
        .execute(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Example protected route: returns the logged-in user's own account.
pub async fn me(
    State(pool): State<SqlitePool>,
    Extension(user): Extension<AuthedUser>,
) -> Result<Json<UserInfo>, (StatusCode, String)> {
    let created_at: String = sqlx::query_scalar("SELECT created_at FROM users WHERE id = ?")
        .bind(user.id)
        .fetch_one(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(UserInfo {
        id: user.id,
        username: user.username,
        created_at,
    }))
}
