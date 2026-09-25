//! Bearer-token auth middleware for agent and user endpoints.
//!
//! Routes are grouped in [`super::routes::router`] behind [`require_agent`]
//! or [`require_user`]; handlers read the caller via `Extension<AuthedAgent>`
//! / `Extension<AuthedUser>`.
//!
//! Agent tokens are stored in plaintext in `agents.token`, not hashed — a
//! deliberate simplification so `/agents/pair` can keep returning the token
//! on every poll after approval without a one-time-exposure mechanism.
//! Fine for a trusted-network dev setup; revisit before exposing this more
//! broadly. User session tokens are stored hashed (see [`crate::credentials`]).

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use sqlx::SqlitePool;

use crate::credentials;

#[derive(Clone)]
pub struct AuthedAgent {
    pub id: i64,
}

#[derive(Clone)]
pub struct AuthedUser {
    pub id: i64,
    pub username: String,
    /// The `user_sessions` row this request authenticated with.
    pub session_id: i64,
}

fn bearer_token(req: &Request) -> Option<&str> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// Rejects the request with `401` unless it carries the bearer token of an
/// approved agent; on success inserts [`AuthedAgent`] into the request
/// extensions.
pub async fn require_agent(
    State(pool): State<SqlitePool>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = bearer_token(&req).ok_or(StatusCode::UNAUTHORIZED)?;

    let id: Option<i64> =
        sqlx::query_scalar("SELECT id FROM agents WHERE token = ? AND status = 'approved'")
            .bind(token)
            .fetch_optional(&pool)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let id = id.ok_or(StatusCode::UNAUTHORIZED)?;
    req.extensions_mut().insert(AuthedAgent { id });

    Ok(next.run(req).await)
}

/// Rejects the request with `401` unless it carries an unexpired user
/// session token from `POST /auth/login`; on success inserts [`AuthedUser`]
/// into the request extensions.
pub async fn require_user(
    State(pool): State<SqlitePool>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = bearer_token(&req).ok_or(StatusCode::UNAUTHORIZED)?;
    let token_hash = credentials::hash_token(token);

    let row: Option<(i64, i64, String)> = sqlx::query_as(
        "SELECT s.id, u.id, u.username FROM user_sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ? AND s.expires_at > datetime('now')",
    )
    .bind(&token_hash)
    .fetch_optional(&pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let (session_id, id, username) = row.ok_or(StatusCode::UNAUTHORIZED)?;
    req.extensions_mut().insert(AuthedUser {
        id,
        username,
        session_id,
    });

    Ok(next.run(req).await)
}
