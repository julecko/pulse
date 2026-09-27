//! Periodic deletion of old rows.
//!
//! How long each kind of data is kept: a user's override from
//! `retention_settings` (see `web::retention`) if there is one, else the
//! server config's `[retention]`. A retention of `0` days keeps that data
//! forever. Expired user sessions are always deleted (they're already
//! rejected by `require_user`).
//!
//! Runs once on startup, then every [`CLEANUP_INTERVAL`], and right away
//! whenever a user changes a retention period (see [`Retention::changed`]),
//! so lowering one takes effect at once.

use std::sync::Arc;
use std::time::Duration;

use protocol::{RetentionData, RetentionSetting};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tokio::sync::Notify;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// The server config's `[retention]` section: the defaults, used for data
/// no user has set a retention period for.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetentionConfig {
    /// Days to keep `metrics` rows (by `created_at`). 0 = forever.
    pub metrics_days: u32,
    /// Days to keep `auth_events` rows (by `created_at`, when the server
    /// received them: `occurred_at` comes from the agent and can't be
    /// trusted). 0 = forever.
    pub auth_events_days: u32,
    /// Days to keep resolved `alerts` (by `resolved_at`); active ones are
    /// always kept. 0 = forever.
    pub alerts_days: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            metrics_days: 14,
            auth_events_days: 14,
            alerts_days: 90,
        }
    }
}

/// Retention periods in effect, shared by the cleanup task and the web
/// routes that change them.
pub struct Retention {
    defaults: RetentionConfig,
    wake: Notify,
}

impl Retention {
    pub fn new(defaults: RetentionConfig) -> Arc<Self> {
        Arc::new(Self {
            defaults,
            wake: Notify::new(),
        })
    }

    pub fn default_days(&self, data: RetentionData) -> u32 {
        match data {
            RetentionData::Metrics => self.defaults.metrics_days,
            RetentionData::AuthEvents => self.defaults.auth_events_days,
            RetentionData::Alerts => self.defaults.alerts_days,
        }
    }

    /// Every kind of data's retention period in effect, overrides applied.
    pub async fn settings(&self, pool: &SqlitePool) -> Result<Vec<RetentionSetting>, sqlx::Error> {
        let overrides: Vec<(String, i64, Option<String>, String)> =
            sqlx::query_as("SELECT data, days, updated_by, updated_at FROM retention_settings")
                .fetch_all(pool)
                .await?;

        Ok(RetentionData::ALL
            .into_iter()
            .map(|data| {
                let default_days = self.default_days(data);
                match overrides.iter().find(|o| o.0 == data.as_str()) {
                    Some((_, days, updated_by, updated_at)) => RetentionSetting {
                        data,
                        // The table's CHECK keeps it in range.
                        days: u32::try_from(*days).unwrap_or(default_days),
                        default_days,
                        overridden: true,
                        updated_by: updated_by.clone(),
                        updated_at: Some(updated_at.clone()),
                    },
                    None => RetentionSetting {
                        data,
                        days: default_days,
                        default_days,
                        overridden: false,
                        updated_by: None,
                        updated_at: None,
                    },
                }
            })
            .collect())
    }

    /// A retention period changed: run a cleanup now rather than at the
    /// next hourly one.
    pub fn changed(&self) {
        self.wake.notify_one();
    }
}

/// Table and timestamp column `data` lives in. Fixed here, never user
/// input, so they're safe to put into SQL.
fn table_and_column(data: RetentionData) -> (&'static str, &'static str) {
    match data {
        RetentionData::Metrics => ("metrics", "created_at"),
        RetentionData::AuthEvents => ("auth_events", "created_at"),
        // NULL (still active) never compares older, so only resolved go.
        RetentionData::Alerts => ("alerts", "resolved_at"),
    }
}

pub async fn cleanup_periodically(pool: SqlitePool, retention: Arc<Retention>) {
    let mut ticker = tokio::time::interval(CLEANUP_INTERVAL);
    let mut last: Option<String> = None;
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            () = retention.wake.notified() => {}
        }

        match retention.settings(&pool).await {
            Ok(settings) => {
                let days = settings
                    .iter()
                    .map(|s| format!("{}={}", s.data, s.days))
                    .collect::<Vec<_>>()
                    .join(" ");
                if last.as_ref() != Some(&days) {
                    tracing::info!(days = %days, "retention in effect (days, 0 = forever)");
                    last = Some(days);
                }
                for setting in &settings {
                    let (table, column) = table_and_column(setting.data);
                    delete_older_than(&pool, table, column, setting.days).await;
                }
            }
            Err(err) => tracing::warn!(%err, "reading retention settings failed; skipping cleanup"),
        }
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
