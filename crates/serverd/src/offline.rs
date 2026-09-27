//! Offline alerts: an alert when an approved agent sends no metrics for
//! longer than its `offline_after_secs` (settings: `web::offline`), pushed
//! to every registered device. It resolves, with a second push, as soon as
//! the agent sends metrics again (see [`recovered`], called from
//! `web::metrics::ingest`).
//!
//! [`watch`] checks every [`CHECK_INTERVAL`]. Time the server itself wasn't
//! running doesn't count: agents can't reach a stopped server, so right
//! after a restart every agent would otherwise look offline. "Last seen" is
//! the latest of the agent's last metrics, when its limit was set, and when
//! the server started.
//!
//! At most one offline alert per agent is active. Acknowledging it doesn't
//! resolve it (the agent is still offline); metrics coming back, or turning
//! the check off for the agent, does.

use std::sync::Arc;
use std::time::Duration;

use protocol::AlertSeverity;
use sqlx::SqlitePool;

use crate::alerting::{Alerting, human_duration};
use crate::push::PushMessage;

const CHECK_INTERVAL: Duration = Duration::from_secs(15);

#[derive(sqlx::FromRow)]
struct QuietAgent {
    id: i64,
    hostname: String,
    offline_after_secs: i64,
    last_metrics_at: Option<String>,
}

pub async fn watch(pool: SqlitePool, alerting: Arc<Alerting>) {
    let started_at: String = match sqlx::query_scalar("SELECT datetime('now')")
        .fetch_one(&pool)
        .await
    {
        Ok(now) => now,
        Err(err) => {
            tracing::error!(%err, "offline alerts disabled: reading the time failed");
            return;
        }
    };

    let mut ticker = tokio::time::interval(CHECK_INTERVAL);
    loop {
        ticker.tick().await;
        if let Err(err) = check(&pool, &alerting, &started_at).await {
            tracing::warn!(%err, "offline alert check failed");
        }
    }
}

async fn check(
    pool: &SqlitePool,
    alerting: &Alerting,
    started_at: &str,
) -> Result<(), sqlx::Error> {
    // SQLite's two-argument MAX() is the larger value; timestamps are all
    // `YYYY-MM-DD HH:MM:SS` UTC, so they compare as text.
    let quiet: Vec<QuietAgent> = sqlx::query_as(
        "SELECT a.id, a.hostname, a.offline_after_secs, a.last_metrics_at FROM agents a
         WHERE a.status = 'approved' AND a.offline_after_secs IS NOT NULL
           AND MAX(COALESCE(a.last_metrics_at, a.offline_after_set_at), a.offline_after_set_at, ?)
               < datetime('now', '-' || a.offline_after_secs || ' seconds')
           AND NOT EXISTS (
               SELECT 1 FROM alerts al JOIN offline_alerts o ON o.alert_id = al.id
               WHERE al.agent_id = a.id AND al.resolved_at IS NULL)",
    )
    .bind(started_at)
    .fetch_all(pool)
    .await?;

    for agent in quiet {
        let title = format!("{} stopped sending metrics", agent.hostname);
        let message = match &agent.last_metrics_at {
            Some(last) => format!(
                "no metrics for over {}; last received {last} UTC",
                human_duration(agent.offline_after_secs)
            ),
            None => format!(
                "no metrics for over {}; none received yet",
                human_duration(agent.offline_after_secs)
            ),
        };
        let severity = AlertSeverity::Critical;

        let mut tx = pool.begin().await?;
        let alert_id: i64 = sqlx::query_scalar(
            "INSERT INTO alerts (agent_id, severity, title, message) VALUES (?, ?, ?, ?)
             RETURNING id",
        )
        .bind(agent.id)
        .bind(severity.as_str())
        .bind(&title)
        .bind(&message)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO offline_alerts (alert_id) VALUES (?)")
            .bind(alert_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;

        tracing::warn!(
            alert_id,
            agent_id = agent.id,
            "agent offline: no metrics for too long"
        );
        alerting.push().notify_all(
            pool,
            PushMessage::alert(alert_id, agent.id, severity.as_str(), title, message),
        );
    }
    Ok(())
}

/// Resolves `agent_id`'s active offline alert, if any, returning its ID.
/// Called when it sends metrics again, and when its check is turned off.
pub async fn resolve(pool: &SqlitePool, agent_id: i64) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE alerts SET resolved_at = datetime('now')
         WHERE agent_id = ? AND resolved_at IS NULL
           AND id IN (SELECT alert_id FROM offline_alerts)
         RETURNING id",
    )
    .bind(agent_id)
    .fetch_optional(pool)
    .await
}

/// The agent just sent metrics: note when, and if it was offline, resolve
/// that and push that it's back. Errors are logged, never returned: they
/// mustn't fail the ingest.
pub async fn recovered(pool: &SqlitePool, alerting: &Alerting, agent_id: i64) {
    let result = async {
        sqlx::query("UPDATE agents SET last_metrics_at = datetime('now') WHERE id = ?")
            .bind(agent_id)
            .execute(pool)
            .await?;
        let Some(alert_id) = resolve(pool, agent_id).await? else {
            return Ok(());
        };
        let hostname: String = sqlx::query_scalar("SELECT hostname FROM agents WHERE id = ?")
            .bind(agent_id)
            .fetch_one(pool)
            .await?;
        tracing::info!(alert_id, agent_id, "agent back online");
        alerting.push().notify_all(
            pool,
            PushMessage::alert(
                alert_id,
                agent_id,
                AlertSeverity::Info.as_str(),
                format!("{hostname} is sending metrics again"),
                "its offline alert is resolved".to_string(),
            ),
        );
        Ok::<_, sqlx::Error>(())
    }
    .await;
    if let Err(err) = result {
        tracing::warn!(%err, agent_id, "updating offline state failed");
    }
}
