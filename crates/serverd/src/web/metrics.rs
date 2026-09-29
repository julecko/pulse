//! Metrics snapshots sent by agents every `interval_secs`, stored one row
//! per snapshot in the `metrics` table (old rows are pruned by
//! `crate::db::retention`).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use protocol::{
    CpuInfo, DiskInfo, LinuxInfo, MAX_SERIES_POINTS, MAX_SERIES_RANGE_SECS, MemoryInfo, Metrics,
    MetricsRecord, MetricsSeries, NetworkInfo, NetworkInterfaceInfo, SeriesPoint,
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
    /// Only snapshots older than this one: pass the last `id` of a page to
    /// get the next (older) one.
    before_id: Option<i64>,
}

/// Most recent snapshots for one agent, newest first. `?limit=` defaults to
/// 20, capped at 1000; `?before_id=` pages back through older ones.
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
         FROM metrics WHERE agent_id = ? AND id < ? ORDER BY id DESC LIMIT ?",
    )
    .bind(id)
    .bind(query.before_id.unwrap_or(i64::MAX))
    .bind(limit)
    .fetch_all(&pool)
    .await
    .map_err(super::internal_error)?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

const DEFAULT_SERIES_RANGE_SECS: i64 = 24 * 3600;
const DEFAULT_SERIES_POINTS: i64 = 300;

#[derive(Deserialize)]
pub struct SeriesQuery {
    range_secs: Option<i64>,
    points: Option<i64>,
}

/// The columns a series needs, one row per snapshot.
#[derive(sqlx::FromRow)]
struct SeriesRow {
    at: i64,
    cpu_global_usage_percent: Option<f32>,
    memory_total_bytes: Option<i64>,
    memory_used_bytes: Option<i64>,
    memory_swap_total_bytes: Option<i64>,
    memory_swap_used_bytes: Option<i64>,
    disks: String,
    linux_load_avg_one: Option<f64>,
    linux_load_avg_five: Option<f64>,
    linux_load_avg_fifteen: Option<f64>,
    network_rx_bytes_per_sec: Option<f64>,
    network_tx_bytes_per_sec: Option<f64>,
}

/// One agent's metrics over the last `?range_secs=` (default a day, at
/// most [`MAX_SERIES_RANGE_SECS`]), averaged into at most `?points=`
/// buckets (default 300, at most [`MAX_SERIES_POINTS`]); see
/// [`MetricsSeries`].
pub async fn series(
    State(pool): State<SqlitePool>,
    Path(id): Path<i64>,
    Query(query): Query<SeriesQuery>,
) -> Result<Json<MetricsSeries>, (StatusCode, String)> {
    let range = query
        .range_secs
        .unwrap_or(DEFAULT_SERIES_RANGE_SECS)
        .clamp(60, MAX_SERIES_RANGE_SECS);
    let points = query
        .points
        .unwrap_or(DEFAULT_SERIES_POINTS)
        .clamp(2, MAX_SERIES_POINTS);
    // Rounded up, so `range` fits in `points` buckets.
    let bucket_secs = (range + points - 1) / points;

    let until: i64 = sqlx::query_scalar("SELECT CAST(strftime('%s', 'now') AS INTEGER)")
        .fetch_one(&pool)
        .await
        .map_err(super::internal_error)?;
    let since = until - range;

    let rows: Vec<SeriesRow> = sqlx::query_as(
        "SELECT CAST(strftime('%s', created_at) AS INTEGER) AS at,
                cpu_global_usage_percent,
                memory_total_bytes, memory_used_bytes,
                memory_swap_total_bytes, memory_swap_used_bytes,
                disks,
                linux_load_avg_one, linux_load_avg_five, linux_load_avg_fifteen,
                network_rx_bytes_per_sec, network_tx_bytes_per_sec
         FROM metrics
         WHERE agent_id = ? AND created_at >= datetime(?, 'unixepoch')
         ORDER BY created_at, id",
    )
    .bind(id)
    .bind(since)
    .fetch_all(&pool)
    .await
    .map_err(super::internal_error)?;

    Ok(Json(MetricsSeries {
        since,
        until,
        bucket_secs,
        points: bucket(rows, since, bucket_secs),
    }))
}

/// Running averages of one bucket.
#[derive(Default)]
struct Bucket {
    samples: u32,
    cpu: Mean,
    cpu_max: Option<f32>,
    memory: Mean,
    swap: Mean,
    disk: Mean,
    load_one: Mean,
    load_five: Mean,
    load_fifteen: Mean,
    net_rx: Mean,
    net_tx: Mean,
}

#[derive(Default)]
struct Mean {
    sum: f64,
    count: u32,
}

impl Mean {
    fn add(&mut self, v: Option<f64>) {
        if let Some(v) = v.filter(|v| v.is_finite()) {
            self.sum += v;
            self.count += 1;
        }
    }

    fn get(&self) -> Option<f64> {
        (self.count > 0).then(|| self.sum / f64::from(self.count))
    }
}

/// `used` as a percentage of `total`; `None` without a total.
fn percent(used: Option<i64>, total: Option<i64>) -> Option<f64> {
    let total = total.filter(|t| *t > 0)?;
    Some(used.unwrap_or(0) as f64 * 100.0 / total as f64)
}

/// The fullest non-removable filesystem's used percentage (any, if all are
/// removable), from the stored `disks` JSON.
fn fullest_disk_percent(disks_json: &str) -> Option<f64> {
    let disks: Vec<DiskInfo> = serde_json::from_str(disks_json).ok()?;
    let sized = || disks.iter().filter(|d| d.total_bytes > 0);
    let pick = if sized().any(|d| !d.removable) {
        sized().filter(|d| !d.removable).collect::<Vec<_>>()
    } else {
        sized().collect()
    };
    pick.into_iter()
        .map(|d| {
            d.total_bytes.saturating_sub(d.available_bytes) as f64 * 100.0 / d.total_bytes as f64
        })
        .reduce(f64::max)
}

/// Averages `rows` (oldest first) into buckets of `bucket_secs` from `since`.
fn bucket(rows: Vec<SeriesRow>, since: i64, bucket_secs: i64) -> Vec<SeriesPoint> {
    let mut points = Vec::new();
    let mut current: Option<(i64, Bucket)> = None;
    for row in rows {
        let at = since + (row.at - since).max(0) / bucket_secs * bucket_secs;
        if current.as_ref().is_some_and(|(start, _)| *start != at) {
            points.extend(current.take().map(finish));
        }
        let (_, b) = current.get_or_insert_with(|| (at, Bucket::default()));
        b.samples += 1;
        let cpu = row.cpu_global_usage_percent;
        b.cpu.add(cpu.map(f64::from));
        if let Some(cpu) = cpu.filter(|c| c.is_finite()) {
            b.cpu_max = Some(b.cpu_max.map_or(cpu, |m| m.max(cpu)));
        }
        b.memory
            .add(percent(row.memory_used_bytes, row.memory_total_bytes));
        b.swap.add(percent(
            row.memory_swap_used_bytes,
            row.memory_swap_total_bytes,
        ));
        b.disk.add(fullest_disk_percent(&row.disks));
        b.load_one.add(row.linux_load_avg_one);
        b.load_five.add(row.linux_load_avg_five);
        b.load_fifteen.add(row.linux_load_avg_fifteen);
        b.net_rx.add(row.network_rx_bytes_per_sec);
        b.net_tx.add(row.network_tx_bytes_per_sec);
    }
    points.extend(current.map(finish));
    points
}

fn finish((at, b): (i64, Bucket)) -> SeriesPoint {
    let f32_of = |m: &Mean| m.get().map(|v| v as f32);
    SeriesPoint {
        at,
        samples: b.samples,
        cpu_percent: f32_of(&b.cpu),
        cpu_max_percent: b.cpu_max,
        memory_percent: f32_of(&b.memory),
        swap_percent: f32_of(&b.swap),
        disk_percent: f32_of(&b.disk),
        load_one: b.load_one.get(),
        load_five: b.load_five.get(),
        load_fifteen: b.load_fifteen.get(),
        net_rx_bytes_per_sec: b.net_rx.get(),
        net_tx_bytes_per_sec: b.net_tx.get(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(at: i64, cpu: f32) -> SeriesRow {
        SeriesRow {
            at,
            cpu_global_usage_percent: Some(cpu),
            memory_total_bytes: Some(1000),
            memory_used_bytes: Some(250),
            memory_swap_total_bytes: Some(0),
            memory_swap_used_bytes: Some(0),
            disks: r#"[{"name":"sda1","mount_point":"/","file_system":"ext4","total_bytes":100,"available_bytes":40,"removable":false},
                       {"name":"sdb1","mount_point":"/media/usb","file_system":"vfat","total_bytes":100,"available_bytes":1,"removable":true}]"#
                .to_string(),
            linux_load_avg_one: Some(1.0),
            linux_load_avg_five: None,
            linux_load_avg_fifteen: None,
            network_rx_bytes_per_sec: Some(100.0),
            network_tx_bytes_per_sec: None,
        }
    }

    #[test]
    fn averages_into_buckets_and_skips_empty_ones() {
        // Buckets of 60 s from t=1000: [1000, 1060), [1060, 1120), ...
        let points = bucket(
            vec![row(1000, 10.0), row(1030, 30.0), row(1200, 50.0)],
            1000,
            60,
        );
        assert_eq!(points.len(), 2);
        assert_eq!(points[0].at, 1000);
        assert_eq!(points[0].samples, 2);
        assert_eq!(points[0].cpu_percent, Some(20.0));
        assert_eq!(points[0].cpu_max_percent, Some(30.0));
        assert_eq!(points[0].memory_percent, Some(25.0));
        // Swap total 0: no swap, not 0 %.
        assert_eq!(points[0].swap_percent, None);
        // The USB stick is fuller, but removable.
        assert_eq!(points[0].disk_percent, Some(60.0));
        assert_eq!(points[0].load_one, Some(1.0));
        assert_eq!(points[0].load_five, None);
        assert_eq!(points[0].net_rx_bytes_per_sec, Some(100.0));
        // Nothing between 1060 and 1180.
        assert_eq!(points[1].at, 1180);
        assert_eq!(points[1].samples, 1);
    }

    #[tokio::test]
    async fn series_and_paging_from_the_database() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let agent_id: i64 = sqlx::query_scalar(
            "INSERT INTO agents (hostname, public_ip, os_name, os_version, kernel_version, arch,
                                 fingerprint, status)
             VALUES ('web01', '192.0.2.1', 'linux', '1', '6', 'x86_64', 'fp', 'approved')
             RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        // Two hours ago (outside a 1 h range), then 30 and 29 minutes ago.
        for (mins_ago, cpu) in [(120, 90.0), (30, 10.0), (29, 20.0)] {
            sqlx::query(
                "INSERT INTO metrics (agent_id, created_at, cpu_global_usage_percent)
                 VALUES (?, datetime('now', ?), ?)",
            )
            .bind(agent_id)
            .bind(format!("-{mins_ago} minutes"))
            .bind(cpu)
            .execute(&pool)
            .await
            .unwrap();
        }

        let Json(s) = series(
            State(pool.clone()),
            Path(agent_id),
            Query(SeriesQuery {
                range_secs: Some(3600),
                points: Some(6),
            }),
        )
        .await
        .unwrap();
        assert_eq!(s.until - s.since, 3600);
        assert_eq!(s.bucket_secs, 600);
        let samples: u32 = s.points.iter().map(|p| p.samples).sum();
        assert_eq!(samples, 2);
        let cpu: Vec<f32> = s.points.iter().filter_map(|p| p.cpu_max_percent).collect();
        assert!(cpu.iter().all(|c| *c < 90.0), "{cpu:?}");
        assert!(s.points.iter().all(|p| p.memory_percent.is_none()));

        let page = |before_id: Option<i64>| {
            let pool = pool.clone();
            async move {
                list(
                    State(pool),
                    Path(agent_id),
                    Query(ListQuery {
                        limit: Some(2),
                        before_id,
                    }),
                )
                .await
                .unwrap()
                .0
            }
        };
        let first = page(None).await;
        assert_eq!(first.len(), 2);
        let older = page(Some(first[1].id)).await;
        assert_eq!(older.len(), 1);
        assert!(older[0].id < first[1].id);
    }

    #[test]
    fn disk_percent_falls_back_to_removable_disks() {
        let only_usb = r#"[{"name":"sdb1","mount_point":"/media/usb","file_system":"vfat","total_bytes":200,"available_bytes":50,"removable":true}]"#;
        assert_eq!(fullest_disk_percent(only_usb), Some(75.0));
        assert_eq!(fullest_disk_percent("[]"), None);
        assert_eq!(fullest_disk_percent("not json"), None);
    }
}
