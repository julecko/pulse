//! Bearer-token auth middleware for agent endpoints.
//!
//! Routes that require an authenticated agent are grouped in
//! [`super::routes::router`] behind [`require_agent`]; handlers read the
//! caller via `Extension<AuthedAgent>`.
//!
//! Tokens are stored in plaintext in `agents.token`, not hashed — a
//! deliberate simplification so `/agents/pair` can keep returning the token
//! on every poll after approval without a one-time-exposure mechanism.
//! Fine for a trusted-network dev setup; revisit before exposing this more
//! broadly.

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct AuthedAgent {
    pub id: i64,
}

/// Rejects the request with `401` unless it carries the bearer token of an
/// approved agent; on success inserts [`AuthedAgent`] into the request
/// extensions.
pub async fn require_agent(
    State(pool): State<SqlitePool>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

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
