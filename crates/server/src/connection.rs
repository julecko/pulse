//! Per-connection handling: decode framed reports and pretty-print every one.

use std::fmt::Write as _;
use std::net::SocketAddr;

use protocol::{ProtocolError, Report};
use tokio::io::BufReader;
use tokio::net::TcpStream;

/// Read every framed report on `stream` until the peer hangs up.
pub async fn handle(stream: TcpStream, peer: SocketAddr) -> Result<(), ProtocolError> {
    let mut reader = BufReader::new(stream);

    // A connection may carry one report or a stream of them.
    let mut seq = 0usize;
    while let Some(report) = protocol::read_report_async(&mut reader).await? {
        seq += 1;
        print!("{}", render(&peer, seq, &report));
    }

    if seq == 0 {
        println!("· {peer} connected but sent no reports");
    } else {
        println!("· {peer} disconnected after {seq} report(s)");
    }
    Ok(())
}

/// Format one report as an indented, human-readable block.
fn render(peer: &SocketAddr, seq: usize, report: &Report) -> String {
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
    let _ = writeln!(out, " os         : {os}");
    if let Some(kernel) = &host.kernel_version {
        let _ = writeln!(out, " kernel     : {kernel}");
    }
    let _ = writeln!(out, " schema     : v{}", report.schema_version);
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
fn bar(pct: f32) -> String {
    let filled = ((pct / 100.0) * 20.0).round().clamp(0.0, 20.0) as usize;
    format!("[{}{}]", "█".repeat(filled), "·".repeat(20 - filled))
}

/// Bytes as a binary-prefixed, one-decimal string (`6.1 GiB`).
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
