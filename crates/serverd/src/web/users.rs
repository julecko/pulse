//! User login/logout and an example route protected by
//! [`super::auth::require_user`]. There's deliberately no registration
//! route: users are created with `pulse-server-cli users add`, which writes to
//! the database directly.

use std::sync::{Arc, LazyLock};
use std::time::Instant;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use protocol::{LoginRequest, LoginResponse, UserInfo};
use sqlx::SqlitePool;

use super::auth::AuthedUser;
use super::rate_limit::{self, RateLimiter};
use crate::credentials;

/// How long a session from [`login`] stays valid; from `[web] session_ttl_hours`.
#[derive(Clone, Copy)]
pub struct SessionTtl(pub u32);

/// Failed logins per username, from any IP (see
/// [`rate_limit::RateLimitConfig::login_failures_per_user_per_minute`]);
/// `None` when disabled.
#[derive(Clone)]
pub struct UserLoginLimiter(pub Option<Arc<RateLimiter<String>>>);

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
    Extension(UserLoginLimiter(user_limiter)): Extension<UserLoginLimiter>,
    Json(req): Json<LoginRequest>,
) -> Response {
    // A username `pulse-server-cli users add` wouldn't accept can't exist,
    // so reject it before touching the database or the per-user limiter
    // (which would otherwise keep a bucket per junk name). This also means
    // every username logged below is plain `a-z A-Z 0-9 _ - .`: nothing a
    // client sends can forge log lines.
    if !protocol::is_valid_username(&req.username) {
        // Debug-formatted, so newlines and control characters are escaped;
        // cut short so a huge name can't flood the log.
        let shown: String = req
            .username
            .chars()
            .take(protocol::MAX_USERNAME_LEN)
            .collect();
        tracing::warn!(username = ?shown, "failed login: invalid username");
        return (StatusCode::UNAUTHORIZED, INVALID_CREDENTIALS).into_response();
    }

    // Unknown usernames get a bucket too, so being throttled doesn't reveal
    // whether an account exists.
    if let Some(limiter) = &user_limiter
        && let Err(retry_after) = limiter.check(req.username.clone(), Instant::now())
    {
        tracing::warn!(limiter = limiter.name(), username = %req.username, "rate limited");
        return rate_limit::too_many_requests(retry_after);
    }

    match verify_and_create_session(&pool, ttl_hours, req.username.clone(), req.password).await {
        Ok(session) => {
            if let Some(limiter) = &user_limiter {
                limiter.refund(&req.username);
            }
            session.into_response()
        }
        Err(err) => err.into_response(),
    }
}

/// Checks the password and, if it's right, starts a session. `Err` with
/// `401` for wrong credentials.
async fn verify_and_create_session(
    pool: &SqlitePool,
    ttl_hours: u32,
    username: String,
    password: String,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let req = LoginRequest { username, password };
    let user: Option<(i64, String)> =
        sqlx::query_as("SELECT id, password_hash FROM users WHERE username = ?")
            .bind(&req.username)
            .fetch_optional(pool)
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
    .fetch_one(pool)
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
