//! `server user ...`: the only way to create or remove user accounts.
//!
//! There's no HTTP route for this on purpose. Running it requires the same
//! access as the server itself (its config and the SQLite file), so only
//! someone with root / service-user access on the server host can manage
//! users. Passwords are never taken as arguments (they'd end up in shell
//! history and `ps`): they're prompted for on a terminal, or read as one
//! line from stdin when piped.

use std::io::{BufRead, IsTerminal};

use sqlx::SqlitePool;

use crate::credentials;

const USAGE: &str = "usage: server user add <username>
       server user remove <username>
       server user list";

const MIN_PASSWORD_LEN: usize = 8;
const MAX_USERNAME_LEN: usize = 64;

pub async fn run(args: &[String], pool: &SqlitePool) -> Result<(), String> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["add", username] => add(pool, username).await,
        ["remove", username] => remove(pool, username).await,
        ["list"] => list(pool).await,
        _ => Err(USAGE.to_string()),
    }
}

async fn add(pool: &SqlitePool, username: &str) -> Result<(), String> {
    validate_username(username)?;

    let password = read_password()?;
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        ));
    }

    let hash =
        credentials::hash_password(&password).map_err(|e| format!("hashing password: {e}"))?;

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

async fn remove(pool: &SqlitePool, username: &str) -> Result<(), String> {
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

async fn list(pool: &SqlitePool) -> Result<(), String> {
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

fn read_password() -> Result<String, String> {
    if std::io::stdin().is_terminal() {
        let password = rpassword::prompt_password("Password: ").map_err(|e| e.to_string())?;
        let confirm = rpassword::prompt_password("Repeat password: ").map_err(|e| e.to_string())?;
        if password != confirm {
            return Err("passwords do not match".to_string());
        }
        Ok(password)
    } else {
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        Ok(line.trim_end_matches(['\r', '\n']).to_string())
    }
}
