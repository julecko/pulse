//! Periodic deletion of old rows, per `[retention]` in the server config.
//!
//! Runs once on startup and then every [`CLEANUP_INTERVAL`]. A retention of
//! `0` days keeps that table's rows forever. Expired user sessions are
//! always deleted (they're already rejected by `require_user`).

use std::time::Duration;

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetentionConfig {
    /// Days to keep `metrics` rows (by `created_at`). 0 = forever.
    pub metrics_days: u32,
    /// Days to keep `auth_events` rows (by `occurred_at`). 0 = forever.
    pub auth_events_days: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            metrics_days: 14,
            auth_events_days: 14,
        }
    }
}

pub async fn cleanup_periodically(pool: SqlitePool, cfg: RetentionConfig) {
    tracing::info!(
        metrics_days = cfg.metrics_days,
        auth_events_days = cfg.auth_events_days,
        "retention cleanup enabled"
    );

    let mut ticker = tokio::time::interval(CLEANUP_INTERVAL);
    loop {
        ticker.tick().await;
        // Table/column names are fixed here, never user input.
        delete_older_than(&pool, "metrics", "created_at", cfg.metrics_days).await;
        delete_older_than(&pool, "auth_events", "occurred_at", cfg.auth_events_days).await;
        delete_expired_sessions(&pool).await;
    }
}

async fn delete_older_than(pool: &SqlitePool, table: &str, column: &str, days: u32) {
    if days == 0 {
        return;
    }

    let sql = format!("DELETE FROM {table} WHERE {column} < datetime('now', ?)");
    match sqlx::query(&sql)
        .bind(format!("-{days} days"))
        .execute(pool)
        .await
    {
        Ok(result) if result.rows_affected() > 0 => {
            tracing::info!(
                table,
                days,
                deleted = result.rows_affected(),
                "deleted old rows"
            );
        }
        Ok(_) => {}
        Err(err) => tracing::warn!(%err, table, "retention cleanup failed"),
    }
}

async fn delete_expired_sessions(pool: &SqlitePool) {
    match sqlx::query("DELETE FROM user_sessions WHERE expires_at <= datetime('now')")
        .execute(pool)
        .await
    {
        Ok(result) if result.rows_affected() > 0 => {
            tracing::info!(
                deleted = result.rows_affected(),
                "deleted expired user sessions"
            );
        }
        Ok(_) => {}
        Err(err) => tracing::warn!(%err, "expired session cleanup failed"),
    }
}
