//! Bearer-token auth extractor for agent endpoints.
//!
//! Tokens are stored in plaintext in `agents.token`, not hashed — a
//! deliberate simplification so `/agents/pair` can keep returning the token
//! on every poll after approval without a one-time-exposure mechanism.
//! Fine for a trusted-network dev setup; revisit before exposing this more
//! broadly.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use sqlx::SqlitePool;

pub struct AuthedAgent {
    pub id: i64,
}

impl FromRequestParts<SqlitePool> for AuthedAgent {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        pool: &SqlitePool,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let id: Option<i64> =
            sqlx::query_scalar("SELECT id FROM agents WHERE token = ? AND status = 'approved'")
                .bind(token)
                .fetch_optional(pool)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        id.map(|id| AuthedAgent { id })
            .ok_or(StatusCode::UNAUTHORIZED)
    }
}
