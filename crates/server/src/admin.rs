//! Account management for `pulse-server user ...`. Opens the history database
//! directly (blocking) — no running daemon required.

use std::path::Path;

use crate::password;
use crate::store::{SqliteStore, Store, now_unix_ms};

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("database: {0}")]
    Db(String),
    #[error("weak password: {0}")]
    Weak(String),
    #[error("user {0:?} already exists")]
    Exists(String),
    #[error("user {0:?} does not exist")]
    Missing(String),
}

fn open(db: &Path) -> Result<SqliteStore, AdminError> {
    SqliteStore::open(db).map_err(|e| AdminError::Db(e.to_string()))
}

fn db_err(e: impl std::fmt::Display) -> AdminError {
    AdminError::Db(e.to_string())
}

/// Create a new account after enforcing the password policy.
pub fn add_user(db: &Path, name: &str, password_plain: &str) -> Result<(), AdminError> {
    password::check_strength(name, password_plain).map_err(AdminError::Weak)?;
    let hash = password::hash(password_plain).map_err(AdminError::Weak)?;
    let store = open(db)?;
    if !store
        .create_user(name, &hash, now_unix_ms())
        .map_err(db_err)?
    {
        return Err(AdminError::Exists(name.to_string()));
    }
    Ok(())
}

/// Change an existing account's password (also enforces the policy).
pub fn set_password(db: &Path, name: &str, password_plain: &str) -> Result<(), AdminError> {
    password::check_strength(name, password_plain).map_err(AdminError::Weak)?;
    let hash = password::hash(password_plain).map_err(AdminError::Weak)?;
    let store = open(db)?;
    if !store.set_password(name, &hash).map_err(db_err)? {
        return Err(AdminError::Missing(name.to_string()));
    }
    Ok(())
}

/// Delete an account and all of its sessions.
pub fn remove_user(db: &Path, name: &str) -> Result<(), AdminError> {
    let store = open(db)?;
    if !store.delete_user(name).map_err(db_err)? {
        return Err(AdminError::Missing(name.to_string()));
    }
    Ok(())
}

/// `(name, created_ms)` for every account, sorted by name.
pub fn list_users(db: &Path) -> Result<Vec<(String, u64)>, AdminError> {
    let store = open(db)?;
    Ok(store
        .list_users()
        .map_err(db_err)?
        .into_iter()
        .map(|u| (u.name, u.created_ms))
        .collect())
}
