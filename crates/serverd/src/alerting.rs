//! Evaluates alert rules against each metrics snapshot an agent sends (see
//! `web::metrics::ingest`), recording and resolving alerts.
//!
//! For each enabled rule that applies to the agent (its own, or one for
//! every agent) and whose metric the snapshot has:
//! - condition holds: once it has held for the rule's `duration_secs`
//!   (counted from the first matching snapshot, as long as every snapshot
//!   since matched), an alert is recorded, and pushed if the rule says
//!   `notify`. At most one alert per rule and agent is active at a time
//!   (unique index), so a condition that keeps holding doesn't fire again.
//! - condition doesn't hold: the active alert, if any, is resolved.
//!
//! When each condition started holding is kept in memory only, so after a
//! restart a `duration_secs` window starts over.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use protocol::{AlertMetric, AlertOperator, AlertSeverity, Metrics};
use sqlx::SqlitePool;

use crate::push::{AlertPush, Push};

/// Longest mount point shown in an alert message.
const MAX_DETAIL_CHARS: usize = 64;

pub struct Alerting {
    push: Push,
    /// (rule, agent) -> when its condition started holding.
    holding_since: Mutex<HashMap<(i64, i64), Instant>>,
}

#[derive(sqlx::FromRow)]
struct RuleRow {
    id: i64,
    name: String,
    metric: String,
    operator: String,
    threshold: f64,
    duration_secs: i64,
    severity: String,
    notify: bool,
}

impl Alerting {
    pub fn new(push: Push) -> Arc<Self> {
        Arc::new(Self {
            push,
            holding_since: Mutex::new(HashMap::new()),
        })
    }

    /// Checks `agent_id`'s rules against the snapshot it just sent. Errors
    /// are logged, never returned: they mustn't fail the ingest.
    pub async fn evaluate(&self, pool: &SqlitePool, agent_id: i64, metrics: &Metrics) {
        if let Err(err) = self.evaluate_inner(pool, agent_id, metrics).await {
            tracing::warn!(%err, agent_id, "alert rule evaluation failed");
        }
    }

    async fn evaluate_inner(
        &self,
        pool: &SqlitePool,
        agent_id: i64,
        metrics: &Metrics,
    ) -> Result<(), sqlx::Error> {
        let rules: Vec<RuleRow> = sqlx::query_as(
            "SELECT id, name, metric, operator, threshold, duration_secs, severity, notify
             FROM alert_rules WHERE enabled = 1 AND (agent_id IS NULL OR agent_id = ?)",
        )
        .bind(agent_id)
        .fetch_all(pool)
        .await?;

        self.forget_stale(agent_id, &rules);

        let now = Instant::now();
        let mut hostname: Option<String> = None;
        for rule in &rules {
            let (Ok(metric), Ok(operator), Ok(severity)) = (
                AlertMetric::from_str(&rule.metric),
                AlertOperator::from_str(&rule.operator),
                AlertSeverity::from_str(&rule.severity),
            ) else {
                tracing::warn!(
                    rule_id = rule.id,
                    "skipping alert rule with unknown metric, operator or severity"
                );
                continue;
            };
            // Nothing to judge by (e.g. no swap): leave the state as it is.
            let Some((value, detail)) = metric_value(metrics, metric) else {
                continue;
            };

            let key = (rule.id, agent_id);
            if !operator.holds(value, rule.threshold) {
                self.lock().remove(&key);
                resolve(pool, rule.id, agent_id).await?;
                continue;
            }

            let since = *self.lock().entry(key).or_insert(now);
            let duration = Duration::from_secs(rule.duration_secs.max(0) as u64);
            if now.duration_since(since) < duration {
                continue;
            }
            // Already firing: nothing to do. (Checked first because an
            // INSERT that hits the conflict below still uses up an id.)
            let active: Option<i64> = sqlx::query_scalar(
                "SELECT id FROM alerts WHERE rule_id = ? AND agent_id = ? AND resolved_at IS NULL",
            )
            .bind(rule.id)
            .bind(agent_id)
            .fetch_optional(pool)
            .await?;
            if active.is_some() {
                continue;
            }

            if hostname.is_none() {
                hostname = sqlx::query_scalar("SELECT hostname FROM agents WHERE id = ?")
                    .bind(agent_id)
                    .fetch_optional(pool)
                    .await?;
            }
            let title = format!(
                "{} on {}",
                rule.name,
                hostname.as_deref().unwrap_or("unknown host")
            );
            let message = format!(
                "{metric} {value:.1}{detail} {operator} {}{}",
                rule.threshold,
                if rule.duration_secs > 0 {
                    format!(" (for {})", human_duration(rule.duration_secs))
                } else {
                    String::new()
                },
                detail = detail.map(|d| format!(" ({d})")).unwrap_or_default(),
            );

            // Only conflicts (no row back) if another snapshot fired it just now.
            let fired: Option<i64> = sqlx::query_scalar(
                "INSERT INTO alerts (rule_id, agent_id, severity, title, message)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT (rule_id, agent_id) WHERE resolved_at IS NULL DO NOTHING
                 RETURNING id",
            )
            .bind(rule.id)
            .bind(agent_id)
            .bind(severity.as_str())
            .bind(&title)
            .bind(&message)
            .fetch_optional(pool)
            .await?;

            if let Some(alert_id) = fired {
                tracing::info!(alert_id, rule_id = rule.id, agent_id, %message, "alert fired");
                if rule.notify {
                    self.push.notify_all(
                        pool,
                        AlertPush {
                            alert_id,
                            agent_id,
                            severity: severity.as_str().to_string(),
                            title,
                            message,
                        },
                    );
                }
            }
        }
        Ok(())
    }

    /// Drops state for rules that no longer apply to `agent_id` (deleted,
    /// disabled, ...), so the map doesn't grow and a re-enabled rule
    /// starts its window over.
    fn forget_stale(&self, agent_id: i64, rules: &[RuleRow]) {
        self.lock().retain(|&(rule_id, agent), _| {
            agent != agent_id || rules.iter().any(|r| r.id == rule_id)
        });
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(i64, i64), Instant>> {
        // Nothing in here can panic mid-update, so a poisoned lock is fine.
        self.holding_since.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Resolves the active alert of `rule_id` for `agent_id`, if there is one.
async fn resolve(pool: &SqlitePool, rule_id: i64, agent_id: i64) -> Result<(), sqlx::Error> {
    let result = sqlx::query(
        "UPDATE alerts SET resolved_at = datetime('now')
         WHERE rule_id = ? AND agent_id = ? AND resolved_at IS NULL",
    )
    .bind(rule_id)
    .bind(agent_id)
    .execute(pool)
    .await?;
    if result.rows_affected() > 0 {
        tracing::info!(rule_id, agent_id, "alert resolved");
    }
    Ok(())
}

/// Resolves every active alert of `rule_id`, for when the rule is disabled
/// or deleted and so can't resolve them itself anymore.
pub async fn resolve_rule(pool: &SqlitePool, rule_id: i64) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "UPDATE alerts SET resolved_at = datetime('now') WHERE rule_id = ? AND resolved_at IS NULL",
    )
    .bind(rule_id)
    .execute(pool)
    .await?
    .rows_affected())
}

/// `metric`'s value in `m`, plus what it refers to when that isn't obvious
/// (the fullest disk's mount point); `None` if the snapshot doesn't have it.
fn metric_value(m: &Metrics, metric: AlertMetric) -> Option<(f64, Option<String>)> {
    let percent = |used: u64, total: u64| (total > 0).then(|| used as f64 / total as f64 * 100.0);
    match metric {
        AlertMetric::CpuUsagePercent => m
            .cpu
            .as_ref()
            .map(|c| (f64::from(c.global_usage_percent), None)),
        AlertMetric::MemoryUsedPercent => m
            .memory
            .as_ref()
            .and_then(|mem| percent(mem.used_bytes, mem.total_bytes))
            .map(|v| (v, None)),
        AlertMetric::SwapUsedPercent => m
            .memory
            .as_ref()
            .and_then(|mem| percent(mem.swap_used_bytes, mem.swap_total_bytes))
            .map(|v| (v, None)),
        AlertMetric::DiskUsedPercent => m
            .disks
            .iter()
            .filter_map(|d| {
                percent(
                    d.total_bytes.saturating_sub(d.available_bytes),
                    d.total_bytes,
                )
                .map(|v| (v, &d.mount_point))
            })
            .max_by(|a, b| a.0.total_cmp(&b.0))
            .map(|(v, mount)| {
                // Agent-supplied: make it safe to show and keep it short.
                let mount: String = protocol::escape_for_display(mount)
                    .chars()
                    .take(MAX_DETAIL_CHARS)
                    .collect();
                (v, Some(mount))
            }),
        AlertMetric::LoadAvgOne => m.linux.as_ref().map(|l| (l.load_avg_one, None)),
        AlertMetric::LoadAvgFive => m.linux.as_ref().map(|l| (l.load_avg_five, None)),
        AlertMetric::LoadAvgFifteen => m.linux.as_ref().map(|l| (l.load_avg_fifteen, None)),
    }
}

/// `300` -> `5m`, `7200` -> `2h`, `90` -> `90s`.
pub fn human_duration(secs: i64) -> String {
    if secs >= 3600 && secs % 3600 == 0 {
        format!("{}h", secs / 3600)
    } else if secs >= 60 && secs % 60 == 0 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

#[cfg(test)]
mod tests {
    use protocol::{CpuInfo, DiskInfo, MemoryInfo};

    use super::*;

    fn disk(mount: &str, total: u64, available: u64) -> DiskInfo {
        DiskInfo {
            name: "sda".into(),
            mount_point: mount.into(),
            file_system: "ext4".into(),
            total_bytes: total,
            available_bytes: available,
            removable: false,
        }
    }

    #[test]
    fn computes_metric_values() {
        let m = Metrics {
            cpu: Some(CpuInfo {
                global_usage_percent: 42.5,
                per_core_usage_percent: vec![],
                core_count: 1,
            }),
            memory: Some(MemoryInfo {
                total_bytes: 200,
                used_bytes: 50,
                free_bytes: 150,
                swap_total_bytes: 0,
                swap_used_bytes: 0,
            }),
            disks: vec![
                disk("/", 100, 60),
                disk("/var", 100, 10),
                disk("/empty", 0, 0),
            ],
            linux: None,
        };
        assert_eq!(
            metric_value(&m, AlertMetric::CpuUsagePercent),
            Some((42.5, None))
        );
        assert_eq!(
            metric_value(&m, AlertMetric::MemoryUsedPercent),
            Some((25.0, None))
        );
        // No swap and no load average: nothing to judge by.
        assert_eq!(metric_value(&m, AlertMetric::SwapUsedPercent), None);
        assert_eq!(metric_value(&m, AlertMetric::LoadAvgOne), None);
        assert_eq!(
            metric_value(&m, AlertMetric::DiskUsedPercent),
            Some((90.0, Some("/var".to_string())))
        );
    }

    #[test]
    fn escapes_disk_mount_points() {
        let m = Metrics {
            disks: vec![disk("/x\x1b[2J", 100, 0)],
            ..Metrics::default()
        };
        let (_, detail) = metric_value(&m, AlertMetric::DiskUsedPercent).unwrap();
        assert_eq!(detail.as_deref(), Some("/x\\x1b[2J"));
    }

    #[test]
    fn formats_durations() {
        assert_eq!(human_duration(300), "5m");
        assert_eq!(human_duration(7200), "2h");
        assert_eq!(human_duration(90), "90s");
        assert_eq!(human_duration(0), "0s");
    }
}
