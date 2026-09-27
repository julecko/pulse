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

/// Longest username.
pub const MAX_USERNAME_LEN: usize = 64;

/// Whether `username` is one `pulse-server-cli users add` accepts: 1 to
/// [`MAX_USERNAME_LEN`] characters of `a-z A-Z 0-9 _ - .`. The server
/// refuses logins for anything else up front, so no other username ever
/// reaches its logs (where e.g. a newline could forge log lines).
pub fn is_valid_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= MAX_USERNAME_LEN
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_usernames() {
        assert!(is_valid_username("alice"));
        assert!(is_valid_username("ops-team_1.bak"));
        assert!(!is_valid_username(""));
        assert!(!is_valid_username("a\nINFO fake line"));
        assert!(!is_valid_username("alice bob"));
        assert!(!is_valid_username("žofia"));
        assert!(!is_valid_username(&"a".repeat(MAX_USERNAME_LEN + 1)));
    }
}
