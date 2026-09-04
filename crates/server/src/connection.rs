#[cfg(debug_assertions)]
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use protocol::{ProtocolError, Report};
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tracing::{info, warn};

use crate::live::Live;
use crate::registry::{Registry, Verdict};
use crate::store::{StoreHandle, now_unix_ms};

#[tracing::instrument(skip_all, fields(peer = %peer))]
pub async fn handle<S>(
    stream: S,
    peer: SocketAddr,
    registry: Arc<Mutex<Registry>>,
    store: StoreHandle,
    live: Arc<Live>,
) -> Result<(), ProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);

    let mut seq = 0usize;
    let mut machine_id = String::new();
    while let Some(report) = protocol::read_report_async(&mut reader).await? {
        let recv_ms = now_unix_ms();
        seq += 1;
        machine_id = report.host.machine_id.clone();

        let total = register(&registry, &report, peer);

        // Structured event — this is what lands in /var/log/pulse in release.
        let m = &report.metrics;
        info!(
            report = seq,
            host = %report.host.hostname,
            machine_id = %report.host.machine_id,
            seen = total,
            cpu_pct = ?m.cpu.as_ref().map(|c| c.global_usage_percent),
            mem_used_bytes = ?m.memory.as_ref().map(|mem| mem.used_bytes),
            disks = m.disks.len(),
            "report received"
        );

        // Full human-readable device dump — debug builds only, straight to the
        // terminal (never routed through tracing / the log file).
        #[cfg(debug_assertions)]
        print!("{}", render(&peer, seq, total, &report));

        // Fan out to live subscribers (in-memory, non-blocking) then persist.
        // A storage failure is logged, not fatal — the live path already ran.
        let report = Arc::new(report);
        live.publish(Arc::clone(&report));
        if let Err(err) = store.insert_report(report, recv_ms, peer.ip()).await {
            warn!(%err, "history insert failed");
        }
    }

    if seq == 0 {
        warn!("peer connected but sent no reports");
    } else {
        info!(machine_id = %machine_id, reports = seq, "peer disconnected");
    }
    Ok(())
}

/// Fold the report into the registry, emitting an event for anything notable.
/// Returns the machine's running report count.
fn register(registry: &Mutex<Registry>, report: &Report, peer: SocketAddr) -> u64 {
    let host = &report.host;
    let mut reg = registry.lock().unwrap();

    let seen = reg.record(&host.machine_id, &host.hostname, peer.ip());
    match seen.verdict {
        Verdict::New => info!(
            machine_id = %host.machine_id,
            hostname = %host.hostname,
            "new host registered"
        ),
        Verdict::Known => {}
        Verdict::Renamed { previous } => info!(
            machine_id = %host.machine_id,
            from = %previous,
            to = %host.hostname,
            "host renamed"
        ),
    }

    if let Some(old) = seen.peer_changed_from {
        info!(
            machine_id = %host.machine_id,
            from = %old,
            to = %peer.ip(),
            "host changed address"
        );
    }

    let clashes = reg.others_named(&host.hostname, &host.machine_id);
    if !clashes.is_empty() {
        warn!(
            hostname = %host.hostname,
            machine_id = %host.machine_id,
            others = %clashes.join(", "),
            "hostname claimed by multiple machines"
        );
    }

    seen.reports
}

/// Format one report as an indented, human-readable block. Debug builds only —
/// in release this data is not printed anywhere (see the structured event in
/// `handle`).
#[cfg(debug_assertions)]
fn render(peer: &SocketAddr, seq: usize, total: u64, report: &Report) -> String {
    let rule = "─".repeat(64);
    let mut out = String::new();

    let _ = writeln!(out, "\n{rule}");
    let _ = writeln!(out, " report #{seq}  from {peer}");
    let _ = writeln!(out, "{rule}");

    let host = &report.host;
    let os = match (&host.os, &host.os_version) {
        (Some(name), Some(ver)) => format!("{name} {ver}"),
        (Some(name), None) => name.clone(),
        _ => "unknown".to_string(),
    };
    let _ = writeln!(out, " host       : {}", host.hostname);
    let _ = writeln!(out, " machine id : {}", host.machine_id);
    let _ = writeln!(out, " ip         : {} (from tcp peer {peer})", peer.ip());
    let _ = writeln!(out, " os         : {os}");
    if let Some(kernel) = &host.kernel_version {
        let _ = writeln!(out, " kernel     : {kernel}");
    }
    let _ = writeln!(out, " schema     : v{}", report.schema_version);
    let _ = writeln!(out, " seen       : {total} report(s) from this machine");
    let _ = writeln!(
        out,
        " timestamp  : {} ms since epoch",
        report.timestamp_unix_ms
    );
    let _ = writeln!(out, " sections   : {}", report.metrics.section_count());

    let m = &report.metrics;

    let _ = writeln!(out, "\n cpu");
    match &m.cpu {
        Some(cpu) => {
            let _ = writeln!(
                out,
                "   global : {:>5.1}%  {}",
                cpu.global_usage_percent,
                bar(cpu.global_usage_percent)
            );
            let _ = writeln!(out, "   cores  : {}", cpu.core_count);
            for (i, pct) in cpu.per_core_usage_percent.iter().enumerate() {
                let _ = writeln!(out, "     [{i:>2}] {pct:>5.1}%  {}", bar(*pct));
            }
        }
        None => {
            let _ = writeln!(out, "   (not reported)");
        }
    }

    let _ = writeln!(out, "\n memory");
    match &m.memory {
        Some(mem) => {
            let _ = writeln!(
                out,
                "   ram  : {} / {} used   ({} free)",
                human_bytes(mem.used_bytes),
                human_bytes(mem.total_bytes),
                human_bytes(mem.free_bytes),
            );
            let _ = writeln!(
                out,
                "   swap : {} / {} used",
                human_bytes(mem.swap_used_bytes),
                human_bytes(mem.swap_total_bytes),
            );
        }
        None => {
            let _ = writeln!(out, "   (not reported)");
        }
    }

    let _ = writeln!(out, "\n disks ({})", m.disks.len());
    if m.disks.is_empty() {
        let _ = writeln!(out, "   (none reported)");
    } else {
        for d in &m.disks {
            let used = d.total_bytes.saturating_sub(d.available_bytes);
            let _ = writeln!(
                out,
                "   {:<18} {:<8} {:<22} {} free / {} ({} used){}",
                d.name,
                d.file_system,
                d.mount_point,
                human_bytes(d.available_bytes),
                human_bytes(d.total_bytes),
                human_bytes(used),
                if d.removable { "  [removable]" } else { "" },
            );
        }
    }

    match &m.linux {
        Some(lx) => {
            let _ = writeln!(out, "\n linux");
            let _ = writeln!(
                out,
                "   load avg : {:.2}  {:.2}  {:.2}   (1 / 5 / 15 min)",
                lx.load_avg_one, lx.load_avg_five, lx.load_avg_fifteen,
            );
            let _ = writeln!(out, "   uptime   : {}", human_duration(lx.uptime_secs));
        }
        None => {}
    }

    let _ = writeln!(out, "{rule}");
    out
}

/// A 20-cell ASCII meter for a 0..=100 percentage.
#[cfg(debug_assertions)]
fn bar(pct: f32) -> String {
    let filled = ((pct / 100.0) * 20.0).round().clamp(0.0, 20.0) as usize;
    format!("[{}{}]", "█".repeat(filled), "·".repeat(20 - filled))
}

/// Bytes as a binary-prefixed, one-decimal string (`6.1 GiB`).
#[cfg(debug_assertions)]
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut val = bytes as f64;
    let mut unit = 0;
    while val >= 1024.0 && unit < UNITS.len() - 1 {
        val /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{val:.1} {}", UNITS[unit])
    }
}

/// Seconds as `3d 4h 12m` (largest non-zero units only).
#[cfg(debug_assertions)]
fn human_duration(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if mins > 0 || parts.is_empty() {
        parts.push(format!("{mins}m"));
    }
    parts.join(" ")
}
