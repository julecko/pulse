//! `pulse-server-cli users ...`: the only way to create or remove user accounts.
//!
//! Unlike the other commands this doesn't go through the server's HTTP API
//! (there's deliberately no route that creates users): it opens the
//! server's SQLite file directly, so it only works for someone with write
//! access to that file on the server host (root / the service user).
//! Passwords are read with [`crate::prompt::password`], never taken as
//! arguments.

use std::path::{Path, PathBuf};

use pulse_shared::db::DbConfig;
use pulse_shared::password;
use serde::Deserialize;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

use crate::prompt;

const MIN_PASSWORD_LEN: usize = 8;
const MAX_USERNAME_LEN: usize = 64;

/// Just the `[db]` section of the server config; everything else in the
/// file is ignored.
#[derive(Default, Deserialize)]
#[serde(default)]
struct ServerConfigDb {
    db: DbConfig,
}

/// Opens the server database: `--db` if given, else `[db] path` from the
/// server config (same lookup as the server: `PULSE_CONFIG`, then
/// `config/server.toml` in debug / `/etc/pulse-server/server.toml` in release),
/// else the server's default location. Never creates the file or runs
/// migrations — that's the server's job.
pub async fn open(db: Option<PathBuf>) -> Result<SqlitePool, String> {
    let path = match db {
        Some(path) => path,
        None => pulse_shared::config::load::<ServerConfigDb>("server")
            .map_err(|e| e.to_string())?
            .db
            .resolved_path(),
    };

    if !path.exists() {
        return Err(format!(
            "no database at {}; start the server once to create it, or pass --db",
            path.display()
        ));
    }

    let pool = connect(&path)
        .await
        .map_err(|e| format!("opening database {}: {e}", path.display()))?;

    let has_users: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'users')",
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| e.to_string())?;
    if !has_users {
        return Err(format!(
            "{} has no users table; start the server once so it applies its migrations",
            path.display()
        ));
    }

    Ok(pool)
}

async fn connect(path: &Path) -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false);
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
}

pub async fn add(pool: &SqlitePool, username: &str) -> Result<(), String> {
    validate_username(username)?;

    let password = read_password()?;
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        ));
    }

    let hash = password::hash_password(&password).map_err(|e| format!("hashing password: {e}"))?;

    sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind(username)
        .bind(&hash)
        .execute(pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(db) if db.is_unique_violation() => {
                format!("user {username:?} already exists")
            }
            e => e.to_string(),
        })?;

    println!("created user {username}");
    Ok(())
}

pub async fn remove(pool: &SqlitePool, username: &str) -> Result<(), String> {
    // Sessions go with it via ON DELETE CASCADE, logging the user out everywhere.
    let result = sqlx::query("DELETE FROM users WHERE username = ?")
        .bind(username)
        .execute(pool)
        .await
        .map_err(|e| e.to_string())?;

    if result.rows_affected() == 0 {
        return Err(format!("no user named {username:?}"));
    }

    println!("removed user {username}");
    Ok(())
}

pub async fn list(pool: &SqlitePool) -> Result<(), String> {
    let users: Vec<(i64, String, String, i64)> = sqlx::query_as(
        "SELECT u.id, u.username, u.created_at,
                (SELECT COUNT(*) FROM user_sessions s
                 WHERE s.user_id = u.id AND s.expires_at > datetime('now'))
         FROM users u ORDER BY u.id",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;

    if users.is_empty() {
        println!("no users");
        return Ok(());
    }

    println!(
        "{:<4} {:<20} {:<20} {:<8}",
        "ID", "USERNAME", "CREATED_AT", "SESSIONS"
    );
    for (id, username, created_at, sessions) in users {
        println!("{id:<4} {username:<20} {created_at:<20} {sessions:<8}");
    }
    Ok(())
}

fn validate_username(username: &str) -> Result<(), String> {
    let valid = !username.is_empty()
        && username.len() <= MAX_USERNAME_LEN
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if valid {
        Ok(())
    } else {
        Err(format!(
            "username must be 1-{MAX_USERNAME_LEN} characters of a-z, A-Z, 0-9, '_', '-', '.'"
        ))
    }
}

/// New password; typed twice on a terminal to catch typos, one stdin line
/// when piped.
fn read_password() -> Result<String, String> {
    let password = prompt::password("Password: ")?;
    if prompt::stdin_is_terminal() && prompt::password("Repeat password: ")? != password {
        return Err("passwords do not match".to_string());
    }
    Ok(password)
}
