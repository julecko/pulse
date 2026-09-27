//! Alert rules: list, create, enable/disable or toggle `notify`, delete.
//! Evaluated by [`crate::alerting`] on every metrics snapshot.

use std::str::FromStr;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use protocol::{
    AlertMetric, AlertOperator, AlertRule, AlertSeverity, NewAlertRule, UpdateAlertRule,
};
use sqlx::SqlitePool;

use super::auth::AuthedUser;
use crate::alerting;

/// Longest rule name; it's part of every alert title and push.
const MAX_NAME_LEN: usize = 100;
/// Longest `duration_secs` (one week).
const MAX_DURATION_SECS: u32 = 7 * 24 * 60 * 60;
/// Rules are evaluated on every metrics snapshot, so keep that bounded.
const MAX_RULES: i64 = 1000;

const RULE_COLUMNS: &str = "id, name, agent_id, metric, operator, threshold, duration_secs, \
                            severity, notify, enabled, created_by, created_at, updated_at";

#[derive(sqlx::FromRow)]
struct RuleRow {
    id: i64,
    name: String,
    agent_id: Option<i64>,
    metric: String,
    operator: String,
    threshold: f64,
    duration_secs: i64,
    severity: String,
    notify: bool,
    enabled: bool,
    created_by: Option<String>,
    created_at: String,
    updated_at: String,
}

impl TryFrom<RuleRow> for AlertRule {
    type Error = String;

    fn try_from(row: RuleRow) -> Result<Self, String> {
        Ok(AlertRule {
            id: row.id,
            name: row.name,
            agent_id: row.agent_id,
            metric: AlertMetric::from_str(&row.metric)?,
            operator: AlertOperator::from_str(&row.operator)?,
            threshold: row.threshold,
            duration_secs: u32::try_from(row.duration_secs).map_err(|e| e.to_string())?,
            severity: AlertSeverity::from_str(&row.severity)?,
            notify: row.notify,
            enabled: row.enabled,
            created_by: row.created_by,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

fn bad_request(msg: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, msg.into())
}

fn not_found() -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, "alert rule not found".to_string())
}

pub async fn list(
    State(pool): State<SqlitePool>,
) -> Result<Json<Vec<AlertRule>>, (StatusCode, String)> {
    let rows: Vec<RuleRow> = sqlx::query_as(&format!(
        "SELECT {RULE_COLUMNS} FROM alert_rules ORDER BY id"
    ))
    .fetch_all(&pool)
    .await
    .map_err(super::internal_error)?;

    rows.into_iter()
        .map(AlertRule::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map(Json)
        .map_err(super::internal_error)
}

pub async fn create(
    State(pool): State<SqlitePool>,
    Extension(user): Extension<AuthedUser>,
    Json(req): Json<NewAlertRule>,
) -> Result<(StatusCode, Json<AlertRule>), (StatusCode, String)> {
    let name = req.name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME_LEN {
        return Err(bad_request(format!(
            "name must be 1-{MAX_NAME_LEN} characters"
        )));
    }
    if name.chars().any(protocol::is_unsafe_display_char) {
        return Err(bad_request("name must not contain control characters"));
    }
    if !req.threshold.is_finite() {
        return Err(bad_request("threshold must be a finite number"));
    }
    if req.duration_secs > MAX_DURATION_SECS {
        return Err(bad_request(format!(
            "duration_secs must be at most {MAX_DURATION_SECS}"
        )));
    }
    if let Some(agent_id) = req.agent_id {
        let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM agents WHERE id = ?")
            .bind(agent_id)
            .fetch_optional(&pool)
            .await
            .map_err(super::internal_error)?;
        if exists.is_none() {
            return Err(bad_request(format!("agent {agent_id} not found")));
        }
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alert_rules")
        .fetch_one(&pool)
        .await
        .map_err(super::internal_error)?;
    if count >= MAX_RULES {
        return Err((
            StatusCode::CONFLICT,
            format!("at most {MAX_RULES} alert rules; delete some first"),
        ));
    }

    let row: RuleRow = sqlx::query_as(&format!(
        "INSERT INTO alert_rules (name, agent_id, metric, operator, threshold, duration_secs, severity, notify, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         RETURNING {RULE_COLUMNS}"
    ))
    .bind(name)
    .bind(req.agent_id)
    .bind(req.metric.as_str())
    .bind(req.operator.as_str())
    .bind(req.threshold)
    .bind(req.duration_secs)
    .bind(req.severity.as_str())
    .bind(req.notify)
    .bind(&user.username)
    .fetch_one(&pool)
    .await
    .map_err(super::internal_error)?;

    tracing::info!(rule_id = row.id, name = %row.name, by = %user.username, "alert rule created");
    let rule = AlertRule::try_from(row).map_err(super::internal_error)?;
    Ok((StatusCode::CREATED, Json(rule)))
}

/// Enables/disables a rule or toggles its `notify`. Disabling resolves its
/// active alerts, since nothing would resolve them otherwise.
pub async fn update(
    State(pool): State<SqlitePool>,
    Extension(user): Extension<AuthedUser>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateAlertRule>,
) -> Result<Json<AlertRule>, (StatusCode, String)> {
    if req.enabled.is_none() && req.notify.is_none() {
        return Err(bad_request("nothing to update: set enabled and/or notify"));
    }

    let row: Option<RuleRow> = sqlx::query_as(&format!(
        "UPDATE alert_rules
         SET enabled = COALESCE(?, enabled), notify = COALESCE(?, notify), updated_at = datetime('now')
         WHERE id = ?
         RETURNING {RULE_COLUMNS}"
    ))
    .bind(req.enabled)
    .bind(req.notify)
    .bind(id)
    .fetch_optional(&pool)
    .await
    .map_err(super::internal_error)?;
    let row = row.ok_or_else(not_found)?;

    if req.enabled == Some(false) {
        let resolved = alerting::resolve_rule(&pool, id)
            .await
            .map_err(super::internal_error)?;
        if resolved > 0 {
            tracing::info!(rule_id = id, resolved, "resolved alerts of disabled rule");
        }
    }

    tracing::info!(
        rule_id = id,
        enabled = row.enabled,
        notify = row.notify,
        by = %user.username,
        "alert rule updated"
    );
    AlertRule::try_from(row)
        .map(Json)
        .map_err(super::internal_error)
}

/// Deletes a rule. Its alerts stay as history (their `rule_id` is cleared),
/// resolved first if still active.
pub async fn remove(
    State(pool): State<SqlitePool>,
    Extension(user): Extension<AuthedUser>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut tx = pool.begin().await.map_err(super::internal_error)?;
    sqlx::query(
        "UPDATE alerts SET resolved_at = datetime('now') WHERE rule_id = ? AND resolved_at IS NULL",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(super::internal_error)?;
    let result = sqlx::query("DELETE FROM alert_rules WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(super::internal_error)?;
    if result.rows_affected() == 0 {
        return Err(not_found());
    }
    tx.commit().await.map_err(super::internal_error)?;

    tracing::info!(rule_id = id, by = %user.username, "alert rule deleted");
    Ok(StatusCode::NO_CONTENT)
}
