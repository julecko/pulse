use serde::{Deserialize, Serialize};

/// Sent to `POST /auth/login`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Returned by `POST /auth/login`. Send `token` as `Authorization: Bearer`
/// on user routes until `expires_at` (UTC, `YYYY-MM-DD HH:MM:SS`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: String,
}

/// Returned by `GET /users/me`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: i64,
    pub username: String,
    pub created_at: String,
}
