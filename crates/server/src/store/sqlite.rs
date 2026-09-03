//! SQLite-backed [`Store`]. Single connection behind a `Mutex` — the write rate
//! is one row per agent per interval, and reads are small and indexed, so lock
//! contention is a non-issue at this scale. Split into reader/writer connections
//! if that ever changes.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Mutex;

use protocol::Report;
use rusqlite::{Connection, OptionalExtension, params};

use super::{Bucket, HostRow, Store, StoreError};

/// Bump when `SCHEMA` changes shape. A DB written by a newer binary is refused.
const SCHEMA_VERSION: u32 = 1;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
  machine_id     TEXT PRIMARY KEY,
  hostname       TEXT NOT NULL,
  os             TEXT,
  os_version     TEXT,
  kernel_version TEXT,
  first_seen_ms  INTEGER NOT NULL,
  last_seen_ms   INTEGER NOT NULL,
  last_peer      TEXT
);

CREATE TABLE IF NOT EXISTS reports (
  id             INTEGER PRIMARY KEY,
  machine_id     TEXT NOT NULL REFERENCES hosts(machine_id) ON DELETE CASCADE,
  ts_ms          INTEGER NOT NULL,
  recv_ms        INTEGER NOT NULL,
  schema_version INTEGER NOT NULL,
  cpu_pct        REAL,
  mem_used       INTEGER,
  mem_total      INTEGER,
  swap_used      INTEGER,
  swap_total     INTEGER,
  load1          REAL,
  load5          REAL,
  load15         REAL,
  uptime_secs    INTEGER,
  body           BLOB NOT NULL,
  UNIQUE (machine_id, ts_ms)
);

CREATE INDEX IF NOT EXISTS idx_reports_machine_ts ON reports (machine_id, ts_ms);
CREATE INDEX IF NOT EXISTS idx_reports_recv       ON reports (recv_ms);
";

pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        Self::init(Connection::open(path)?)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self, StoreError> {
        // auto_vacuum must be set before the first table is created to take
        // effect; harmless on an already-populated DB.
        conn.execute_batch(
            "PRAGMA auto_vacuum = INCREMENTAL;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA foreign_keys = ON;",
        )?;
        conn.execute_batch(SCHEMA)?;

        let found: Option<u32> = conn
            .query_row("SELECT v FROM meta WHERE k = 'schema_version'", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
            .and_then(|s| s.parse().ok());
        match found {
            None => {
                conn.execute(
                    "INSERT INTO meta (k, v) VALUES ('schema_version', ?1)",
                    params![SCHEMA_VERSION.to_string()],
                )?;
            }
            Some(v) if v > SCHEMA_VERSION => {
                return Err(StoreError::SchemaTooNew {
                    found: v,
                    supported: SCHEMA_VERSION,
                });
            }
            Some(_) => {}
        }

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

/// Run a `SELECT body FROM ...` and MessagePack-decode each blob.
#[allow(dead_code)] // reached only via the read path (HTTP API, follow-up change)
fn decode_reports(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
) -> Result<Vec<Report>, StoreError> {
    let mut stmt = conn.prepare(sql)?;
    let blobs = stmt.query_map(params, |r| r.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for blob in blobs {
        out.push(protocol::decode_body(&blob?)?);
    }
    Ok(out)
}

impl Store for SqliteStore {
    fn insert_report(&self, report: &Report, recv_ms: u64, peer: IpAddr) -> Result<(), StoreError> {
        let body = protocol::encode_body(report)?;
        let h = &report.host;
        let m = &report.metrics;
        let cpu = m.cpu.as_ref();
        let mem = m.memory.as_ref();
        let lx = m.linux.as_ref();

        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO hosts
               (machine_id, hostname, os, os_version, kernel_version,
                first_seen_ms, last_seen_ms, last_peer)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)
             ON CONFLICT(machine_id) DO UPDATE SET
               hostname       = excluded.hostname,
               os             = excluded.os,
               os_version     = excluded.os_version,
               kernel_version = excluded.kernel_version,
               last_seen_ms   = excluded.last_seen_ms,
               last_peer      = excluded.last_peer",
            params![
                h.machine_id,
                h.hostname,
                h.os,
                h.os_version,
                h.kernel_version,
                recv_ms as i64,
                peer.to_string(),
            ],
        )?;
        tx.execute(
            "INSERT INTO reports
               (machine_id, ts_ms, recv_ms, schema_version,
                cpu_pct, mem_used, mem_total, swap_used, swap_total,
                load1, load5, load15, uptime_secs, body)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)
             ON CONFLICT(machine_id, ts_ms) DO NOTHING",
            params![
                h.machine_id,
                report.timestamp_unix_ms as i64,
                recv_ms as i64,
                report.schema_version as i64,
                cpu.map(|c| c.global_usage_percent as f64),
                mem.map(|m| m.used_bytes as i64),
                mem.map(|m| m.total_bytes as i64),
                mem.map(|m| m.swap_used_bytes as i64),
                mem.map(|m| m.swap_total_bytes as i64),
                lx.map(|l| l.load_avg_one),
                lx.map(|l| l.load_avg_five),
                lx.map(|l| l.load_avg_fifteen),
                lx.map(|l| l.uptime_secs as i64),
                body,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn list_hosts(&self) -> Result<Vec<HostRow>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT h.machine_id, h.hostname, h.os, h.os_version, h.kernel_version,
                    h.first_seen_ms, h.last_seen_ms, h.last_peer,
                    (SELECT COUNT(*) FROM reports r WHERE r.machine_id = h.machine_id)
             FROM hosts h
             ORDER BY h.hostname, h.machine_id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(HostRow {
                machine_id: r.get(0)?,
                hostname: r.get(1)?,
                os: r.get(2)?,
                os_version: r.get(3)?,
                kernel_version: r.get(4)?,
                first_seen_ms: r.get::<_, i64>(5)? as u64,
                last_seen_ms: r.get::<_, i64>(6)? as u64,
                last_peer: r.get(7)?,
                report_count: r.get::<_, i64>(8)? as u64,
            })
        })?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    fn latest_per_host(&self) -> Result<Vec<Report>, StoreError> {
        let conn = self.conn.lock().unwrap();
        decode_reports(
            &conn,
            "SELECT r.body FROM reports r
             JOIN (SELECT machine_id, MAX(ts_ms) AS mx FROM reports GROUP BY machine_id) g
               ON g.machine_id = r.machine_id AND g.mx = r.ts_ms",
            [],
        )
    }

    fn latest_for(&self, machine_id: &str) -> Result<Option<Report>, StoreError> {
        let conn = self.conn.lock().unwrap();
        Ok(decode_reports(
            &conn,
            "SELECT body FROM reports WHERE machine_id = ?1 ORDER BY ts_ms DESC LIMIT 1",
            params![machine_id],
        )?
        .pop())
    }

    fn history(
        &self,
        machine_id: &str,
        from_ms: u64,
        to_ms: u64,
        bucket_ms: u64,
    ) -> Result<Vec<Bucket>, StoreError> {
        let bucket = bucket_ms.max(1) as i64;
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT (ts_ms / ?1) * ?1 AS bucket,
                    AVG(cpu_pct), MAX(cpu_pct),
                    AVG(mem_used), MAX(mem_used),
                    AVG(load1), COUNT(*)
             FROM reports
             WHERE machine_id = ?2 AND ts_ms >= ?3 AND ts_ms < ?4
             GROUP BY bucket
             ORDER BY bucket",
        )?;
        let rows = stmt.query_map(
            params![bucket, machine_id, from_ms as i64, to_ms as i64],
            |r| {
                Ok(Bucket {
                    ts_ms: r.get::<_, i64>(0)? as u64,
                    cpu_avg: r.get(1)?,
                    cpu_max: r.get(2)?,
                    mem_used_avg: r.get(3)?,
                    mem_used_max: r.get::<_, Option<i64>>(4)?.map(|v| v as u64),
                    load1_avg: r.get(5)?,
                    samples: r.get::<_, i64>(6)? as u64,
                })
            },
        )?;
        rows.collect::<Result<_, _>>().map_err(Into::into)
    }

    fn recent_reports(
        &self,
        machine_id: &str,
        from_ms: u64,
        to_ms: u64,
        limit: usize,
    ) -> Result<Vec<Report>, StoreError> {
        let conn = self.conn.lock().unwrap();
        let mut reports = decode_reports(
            &conn,
            "SELECT body FROM reports
             WHERE machine_id = ?1 AND ts_ms >= ?2 AND ts_ms < ?3
             ORDER BY ts_ms DESC LIMIT ?4",
            params![machine_id, from_ms as i64, to_ms as i64, limit as i64],
        )?;
        reports.reverse();
        Ok(reports)
    }

    fn prune(&self, cutoff_recv_ms: u64) -> Result<u64, StoreError> {
        let conn = self.conn.lock().unwrap();
        let removed = conn.execute(
            "DELETE FROM reports WHERE recv_ms < ?1",
            params![cutoff_recv_ms as i64],
        )?;
        // Return freed pages to the OS (no-op unless auto_vacuum = INCREMENTAL).
        let _ = conn.execute_batch("PRAGMA incremental_vacuum;");
        Ok(removed as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::{CpuInfo, HostInfo, LinuxInfo, MemoryInfo, Metrics, Report};
    use std::net::Ipv4Addr;

    fn report(machine_id: &str, hostname: &str, ts_ms: u64, cpu: f32) -> Report {
        let mut r = Report::new(
            HostInfo {
                machine_id: machine_id.into(),
                hostname: hostname.into(),
                os: Some("Ubuntu".into()),
                os_version: Some("22.04".into()),
                kernel_version: Some("5.15".into()),
            },
            Metrics {
                cpu: Some(CpuInfo {
                    global_usage_percent: cpu,
                    per_core_usage_percent: vec![cpu, cpu],
                    core_count: 2,
                }),
                memory: Some(MemoryInfo {
                    total_bytes: 16,
                    used_bytes: 8,
                    free_bytes: 8,
                    swap_total_bytes: 4,
                    swap_used_bytes: 1,
                }),
                linux: Some(LinuxInfo {
                    load_avg_one: 0.5,
                    load_avg_five: 0.4,
                    load_avg_fifteen: 0.3,
                    uptime_secs: 100,
                }),
                ..Default::default()
            },
        );
        r.timestamp_unix_ms = ts_ms;
        r
    }

    fn peer() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    #[test]
    fn schema_version_is_recorded() {
        let s = SqliteStore::open_in_memory().unwrap();
        let conn = s.conn.lock().unwrap();
        let v: String = conn
            .query_row("SELECT v FROM meta WHERE k = 'schema_version'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(v, "1");
    }

    #[test]
    fn insert_upserts_host_and_appends_reports() {
        let s = SqliteStore::open_in_memory().unwrap();
        s.insert_report(&report("m1", "alpha", 1_000, 10.0), 1_001, peer())
            .unwrap();
        s.insert_report(&report("m1", "alpha2", 2_000, 20.0), 2_001, peer())
            .unwrap();
        s.insert_report(&report("m2", "beta", 1_500, 5.0), 1_501, peer())
            .unwrap();

        let hosts = s.list_hosts().unwrap();
        assert_eq!(hosts.len(), 2);
        let m1 = hosts.iter().find(|h| h.machine_id == "m1").unwrap();
        assert_eq!(m1.hostname, "alpha2"); // last write wins
        assert_eq!(m1.report_count, 2);
        assert_eq!(m1.first_seen_ms, 1_001);
        assert_eq!(m1.last_seen_ms, 2_001);
    }

    #[test]
    fn duplicate_timestamp_is_ignored() {
        let s = SqliteStore::open_in_memory().unwrap();
        s.insert_report(&report("m1", "a", 1_000, 10.0), 1_001, peer())
            .unwrap();
        s.insert_report(&report("m1", "a", 1_000, 99.0), 1_050, peer())
            .unwrap();
        assert_eq!(s.list_hosts().unwrap()[0].report_count, 1);
        let latest = s.latest_for("m1").unwrap().unwrap();
        assert_eq!(latest.metrics.cpu.unwrap().global_usage_percent, 10.0);
    }

    #[test]
    fn latest_per_host_returns_newest_body() {
        let s = SqliteStore::open_in_memory().unwrap();
        s.insert_report(&report("m1", "a", 1_000, 10.0), 1_001, peer())
            .unwrap();
        s.insert_report(&report("m1", "a", 3_000, 30.0), 3_001, peer())
            .unwrap();
        s.insert_report(&report("m2", "b", 2_000, 20.0), 2_001, peer())
            .unwrap();

        let mut latest = s.latest_per_host().unwrap();
        latest.sort_by_key(|r| r.host.machine_id.clone());
        assert_eq!(latest.len(), 2);
        assert_eq!(latest[0].timestamp_unix_ms, 3_000);
        assert_eq!(latest[1].timestamp_unix_ms, 2_000);
    }

    #[test]
    fn hot_columns_null_when_section_missing() {
        let s = SqliteStore::open_in_memory().unwrap();
        let mut r = report("m1", "a", 1_000, 0.0);
        r.metrics = Metrics::default();
        s.insert_report(&r, 1_001, peer()).unwrap();

        let conn = s.conn.lock().unwrap();
        let (cpu, mem): (Option<f64>, Option<i64>) = conn
            .query_row("SELECT cpu_pct, mem_used FROM reports", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert!(cpu.is_none() && mem.is_none());
        // row still present, body still decodes
        drop(conn);
        assert!(s.latest_for("m1").unwrap().is_some());
    }

    #[test]
    fn recent_reports_respects_range_limit_and_order() {
        let s = SqliteStore::open_in_memory().unwrap();
        for ts in [1_000u64, 2_000, 3_000, 4_000] {
            s.insert_report(&report("m1", "a", ts, ts as f32 / 100.0), ts + 1, peer())
                .unwrap();
        }
        let got = s.recent_reports("m1", 1_500, 4_000, 10).unwrap();
        let ts: Vec<u64> = got.iter().map(|r| r.timestamp_unix_ms).collect();
        assert_eq!(ts, vec![2_000, 3_000]); // [from,to), chronological

        let capped = s.recent_reports("m1", 0, 10_000, 2).unwrap();
        let ts: Vec<u64> = capped.iter().map(|r| r.timestamp_unix_ms).collect();
        assert_eq!(ts, vec![3_000, 4_000]); // newest 2, chronological
    }

    #[test]
    fn history_buckets_aggregate_per_window() {
        let s = SqliteStore::open_in_memory().unwrap();
        // bucket = 1000ms; window A [0,1000): ts 100,900 ; window B [1000,2000): ts 1100
        s.insert_report(&report("m1", "a", 100, 10.0), 101, peer())
            .unwrap();
        s.insert_report(&report("m1", "a", 900, 30.0), 901, peer())
            .unwrap();
        s.insert_report(&report("m1", "a", 1_100, 50.0), 1_101, peer())
            .unwrap();

        let buckets = s.history("m1", 0, 2_000, 1_000).unwrap();
        assert_eq!(buckets.len(), 2);
        assert_eq!(buckets[0].ts_ms, 0);
        assert_eq!(buckets[0].samples, 2);
        assert_eq!(buckets[0].cpu_avg, Some(20.0));
        assert_eq!(buckets[0].cpu_max, Some(30.0));
        assert_eq!(buckets[1].ts_ms, 1_000);
        assert_eq!(buckets[1].samples, 1);
        assert_eq!(buckets[1].cpu_max, Some(50.0));
    }

    #[test]
    fn prune_deletes_strictly_older_and_keeps_host() {
        let s = SqliteStore::open_in_memory().unwrap();
        // recv_ms 99 / 100 / 101, cutoff 100
        s.insert_report(&report("m1", "a", 10, 1.0), 99, peer())
            .unwrap();
        s.insert_report(&report("m1", "a", 20, 2.0), 100, peer())
            .unwrap();
        s.insert_report(&report("m1", "a", 30, 3.0), 101, peer())
            .unwrap();

        assert_eq!(s.prune(100).unwrap(), 1);
        let remaining = s.recent_reports("m1", 0, 1_000, 10).unwrap();
        assert_eq!(remaining.len(), 2);
        // host row survives even if all its reports go
        assert_eq!(s.prune(10_000).unwrap(), 2);
        assert_eq!(s.list_hosts().unwrap().len(), 1);
    }

    #[test]
    fn refuses_a_newer_schema() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA).unwrap();
        conn.execute(
            "INSERT INTO meta (k, v) VALUES ('schema_version', '999')",
            [],
        )
        .unwrap();
        match SqliteStore::init(conn) {
            Err(StoreError::SchemaTooNew { found: 999, .. }) => {}
            other => panic!("expected SchemaTooNew, got {:?}", other.err()),
        }
    }
}
