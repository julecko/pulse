//! Metrics snapshots sent by agents every `interval_secs`, stored one row
//! per snapshot in the `metrics` table (old rows are pruned by
//! `crate::db::retention`).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use protocol::{
    CpuInfo, DiskInfo, LinuxInfo, MemoryInfo, Metrics, MetricsRecord, NetworkInfo,
    NetworkInterfaceInfo,
};
use serde::Deserialize;
use sqlx::SqlitePool;

use super::auth::AuthedAgent;
use crate::alerting::Alerting;

const DEFAULT_LIST_LIMIT: i64 = 20;
const MAX_LIST_LIMIT: i64 = 1000;

/// Upper bounds on a snapshot, far above any real host (agents report
/// real filesystems only, not every mount), so a misbehaving or
/// compromised agent can't store arbitrary amounts of data per row.
const MAX_DISKS: usize = 256;
const MAX_CORES: usize = 1024;
const MAX_NETWORK_INTERFACES: usize = 256;
/// Longest disk name / mount point / file system name.
const MAX_DISK_FIELD_LEN: usize = 1024;
/// Longest network interface name (Linux allows 15 bytes).
const MAX_INTERFACE_NAME_LEN: usize = 64;

/// SQLite integers are signed 64-bit; byte counts never get near the limit,
/// but saturate rather than wrap just in case.
fn to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Stores one snapshot for the calling agent, then checks its alert rules
/// against it (see [`crate::alerting`]). Behind
/// [`super::auth::require_agent`], so `agent_id` always comes from the token.
pub async fn ingest(
    State(pool): State<SqlitePool>,
    Extension(agent): Extension<AuthedAgent>,
    Extension(alerting): Extension<Arc<Alerting>>,
    Json(m): Json<Metrics>,
) -> Result<StatusCode, (StatusCode, String)> {
    if let Err(err) = validate(&m) {
        tracing::warn!(agent_id = agent.id, %err, "rejected metrics");
        return Err((StatusCode::BAD_REQUEST, err));
    }

    let per_core = m
        .cpu
        .as_ref()
        .map(|c| serde_json::to_string(&c.per_core_usage_percent))
        .transpose()
        .map_err(super::internal_error)?;
    let disks = serde_json::to_string(&m.disks).map_err(super::internal_error)?;
    let interfaces = m
        .network
        .as_ref()
        .map(|n| serde_json::to_string(&n.interfaces))
        .transpose()
        .map_err(super::internal_error)?;

    sqlx::query(
        "INSERT INTO metrics (
            agent_id,
            cpu_global_usage_percent, cpu_per_core_usage_percent, cpu_core_count,
            memory_total_bytes, memory_used_bytes, memory_free_bytes,
            memory_swap_total_bytes, memory_swap_used_bytes,
            disks,
            linux_load_avg_one, linux_load_avg_five, linux_load_avg_fifteen, linux_uptime_secs,
            network_rx_bytes_per_sec, network_tx_bytes_per_sec, network_interfaces
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
    .bind(m.network.as_ref().map(|n| n.rx_bytes_per_sec))
    .bind(m.network.as_ref().map(|n| n.tx_bytes_per_sec))
    .bind(interfaces)
    .execute(&pool)
    .await
    .map_err(super::internal_error)?;

    tracing::debug!(agent_id = agent.id, "stored metrics");

    crate::offline::recovered(&pool, &alerting, agent.id).await;
    alerting.evaluate(&pool, agent.id, &m).await;

    Ok(StatusCode::NO_CONTENT)
}

fn validate(m: &Metrics) -> Result<(), String> {
    if m.disks.len() > MAX_DISKS {
        return Err(format!("at most {MAX_DISKS} disks"));
    }
    if let Some(cpu) = &m.cpu
        && (cpu.per_core_usage_percent.len() > MAX_CORES || cpu.core_count > MAX_CORES)
    {
        return Err(format!("at most {MAX_CORES} cores"));
    }
    let too_long = m.disks.iter().any(|d| {
        [&d.name, &d.mount_point, &d.file_system]
            .iter()
            .any(|s| s.len() > MAX_DISK_FIELD_LEN)
    });
    if too_long {
        return Err(format!(
            "disk name, mount point and file system must be at most {MAX_DISK_FIELD_LEN} bytes"
        ));
    }
    if let Some(net) = &m.network {
        if net.interfaces.len() > MAX_NETWORK_INTERFACES {
            return Err(format!(
                "at most {MAX_NETWORK_INTERFACES} network interfaces"
            ));
        }
        if net
            .interfaces
            .iter()
            .any(|i| i.name.len() > MAX_INTERFACE_NAME_LEN)
        {
            return Err(format!(
                "network interface names must be at most {MAX_INTERFACE_NAME_LEN} bytes"
            ));
        }
        let rates = [net.rx_bytes_per_sec, net.tx_bytes_per_sec]
            .into_iter()
            .chain(
                net.interfaces
                    .iter()
                    .flat_map(|i| [i.rx_bytes_per_sec, i.tx_bytes_per_sec]),
            );
        for rate in rates {
            if !rate.is_finite() || rate < 0.0 {
                return Err("network rates must be finite and not negative".to_string());
            }
        }
    }
    Ok(())
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
    network_rx_bytes_per_sec: Option<f64>,
    network_tx_bytes_per_sec: Option<f64>,
    network_interfaces: Option<String>,
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
        let network = row.network_rx_bytes_per_sec.map(|rx| NetworkInfo {
            rx_bytes_per_sec: rx,
            tx_bytes_per_sec: row.network_tx_bytes_per_sec.unwrap_or(0.0),
            interfaces: row
                .network_interfaces
                .as_deref()
                .and_then(|json| serde_json::from_str::<Vec<NetworkInterfaceInfo>>(json).ok())
                .unwrap_or_default(),
        });

        MetricsRecord {
            id: row.id,
            created_at: row.created_at,
            metrics: Metrics {
                cpu,
                memory,
                disks,
                linux,
                network,
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
                linux_load_avg_one, linux_load_avg_five, linux_load_avg_fifteen, linux_uptime_secs,
                network_rx_bytes_per_sec, network_tx_bytes_per_sec, network_interfaces
         FROM metrics WHERE agent_id = ? ORDER BY id DESC LIMIT ?",
    )
    .bind(id)
    .bind(limit)
    .fetch_all(&pool)
    .await
    .map_err(super::internal_error)?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}
