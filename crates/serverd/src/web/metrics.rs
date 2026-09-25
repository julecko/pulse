//! Metrics snapshots sent by agents every `interval_secs`, stored one row
//! per snapshot in the `metrics` table (old rows are pruned by
//! `crate::db::retention`).

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use protocol::{CpuInfo, DiskInfo, LinuxInfo, MemoryInfo, Metrics, MetricsRecord};
use serde::Deserialize;
use sqlx::SqlitePool;

use super::auth::AuthedAgent;

const DEFAULT_LIST_LIMIT: i64 = 20;
const MAX_LIST_LIMIT: i64 = 1000;

/// SQLite integers are signed 64-bit; byte counts never get near the limit,
/// but saturate rather than wrap just in case.
fn to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Stores one snapshot for the calling agent. Behind
/// [`super::auth::require_agent`], so `agent_id` always comes from the token.
pub async fn ingest(
    State(pool): State<SqlitePool>,
    Extension(agent): Extension<AuthedAgent>,
    Json(m): Json<Metrics>,
) -> Result<StatusCode, (StatusCode, String)> {
    let per_core = m
        .cpu
        .as_ref()
        .map(|c| serde_json::to_string(&c.per_core_usage_percent))
        .transpose()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let disks = serde_json::to_string(&m.disks)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    sqlx::query(
        "INSERT INTO metrics (
            agent_id,
            cpu_global_usage_percent, cpu_per_core_usage_percent, cpu_core_count,
            memory_total_bytes, memory_used_bytes, memory_free_bytes,
            memory_swap_total_bytes, memory_swap_used_bytes,
            disks,
            linux_load_avg_one, linux_load_avg_five, linux_load_avg_fifteen, linux_uptime_secs
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(agent.id)
    .bind(m.cpu.as_ref().map(|c| c.global_usage_percent))
    .bind(per_core)
    .bind(m.cpu.as_ref().map(|c| to_i64(c.core_count as u64)))
    .bind(m.memory.as_ref().map(|mem| to_i64(mem.total_bytes)))
    .bind(m.memory.as_ref().map(|mem| to_i64(mem.used_bytes)))
    .bind(m.memory.as_ref().map(|mem| to_i64(mem.free_bytes)))
    .bind(m.memory.as_ref().map(|mem| to_i64(mem.swap_total_bytes)))
    .bind(m.memory.as_ref().map(|mem| to_i64(mem.swap_used_bytes)))
    .bind(disks)
    .bind(m.linux.as_ref().map(|l| l.load_avg_one))
    .bind(m.linux.as_ref().map(|l| l.load_avg_five))
    .bind(m.linux.as_ref().map(|l| l.load_avg_fifteen))
    .bind(m.linux.as_ref().map(|l| to_i64(l.uptime_secs)))
    .execute(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    tracing::debug!(agent_id = agent.id, "stored metrics");

    Ok(StatusCode::NO_CONTENT)
}

#[derive(sqlx::FromRow)]
struct MetricsRow {
    id: i64,
    created_at: String,
    cpu_global_usage_percent: Option<f32>,
    cpu_per_core_usage_percent: Option<String>,
    cpu_core_count: Option<i64>,
    memory_total_bytes: Option<i64>,
    memory_used_bytes: Option<i64>,
    memory_free_bytes: Option<i64>,
    memory_swap_total_bytes: Option<i64>,
    memory_swap_used_bytes: Option<i64>,
    disks: String,
    linux_load_avg_one: Option<f64>,
    linux_load_avg_five: Option<f64>,
    linux_load_avg_fifteen: Option<f64>,
    linux_uptime_secs: Option<i64>,
}

impl From<MetricsRow> for MetricsRecord {
    fn from(row: MetricsRow) -> Self {
        // Each section was written all-or-nothing by `ingest`, so one
        // non-null column means the whole section is present.
        let cpu = row.cpu_global_usage_percent.map(|global| CpuInfo {
            global_usage_percent: global,
            per_core_usage_percent: row
                .cpu_per_core_usage_percent
                .as_deref()
                .and_then(|json| serde_json::from_str(json).ok())
                .unwrap_or_default(),
            core_count: row.cpu_core_count.unwrap_or(0) as usize,
        });
        let memory = row.memory_total_bytes.map(|total| MemoryInfo {
            total_bytes: total as u64,
            used_bytes: row.memory_used_bytes.unwrap_or(0) as u64,
            free_bytes: row.memory_free_bytes.unwrap_or(0) as u64,
            swap_total_bytes: row.memory_swap_total_bytes.unwrap_or(0) as u64,
            swap_used_bytes: row.memory_swap_used_bytes.unwrap_or(0) as u64,
        });
        let linux = row.linux_load_avg_one.map(|one| LinuxInfo {
            load_avg_one: one,
            load_avg_five: row.linux_load_avg_five.unwrap_or(0.0),
            load_avg_fifteen: row.linux_load_avg_fifteen.unwrap_or(0.0),
            uptime_secs: row.linux_uptime_secs.unwrap_or(0) as u64,
        });
        let disks: Vec<DiskInfo> = serde_json::from_str(&row.disks).unwrap_or_default();

        MetricsRecord {
            id: row.id,
            created_at: row.created_at,
            metrics: Metrics {
                cpu,
                memory,
                disks,
                linux,
            },
        }
    }
}

#[derive(Deserialize)]
pub struct ListQuery {
    limit: Option<i64>,
}

/// Most recent snapshots for one agent, newest first. `?limit=` defaults to
/// 20, capped at 1000.
pub async fn list(
    State(pool): State<SqlitePool>,
    Path(id): Path<i64>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<MetricsRecord>>, (StatusCode, String)> {
    let limit = query
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);

    let rows: Vec<MetricsRow> = sqlx::query_as(
        "SELECT id, created_at,
                cpu_global_usage_percent, cpu_per_core_usage_percent, cpu_core_count,
                memory_total_bytes, memory_used_bytes, memory_free_bytes,
                memory_swap_total_bytes, memory_swap_used_bytes,
                disks,
                linux_load_avg_one, linux_load_avg_five, linux_load_avg_fifteen, linux_uptime_secs
         FROM metrics WHERE agent_id = ? ORDER BY id DESC LIMIT ?",
    )
    .bind(id)
    .bind(limit)
    .fetch_all(&pool)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}
