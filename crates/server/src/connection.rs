//! Per-connection handling: decode framed reports and print a summary.

use std::io::BufReader;
use std::net::TcpStream;

use protocol::ProtocolError;

/// Read every framed report on `stream` until the peer hangs up.
pub fn handle(stream: TcpStream) -> Result<(), ProtocolError> {
    let peer = stream.peer_addr().ok();
    let mut reader = BufReader::new(stream);

    // A connection may carry one report or a stream of them.
    while let Some(report) = protocol::read_report(&mut reader)? {
        println!(
            "[{}] {} @ {}ms  cpu={:?}% mem_used={:?} disks={} linux={}",
            peer.map(|p| p.to_string()).unwrap_or_default(),
            report.host.hostname,
            report.timestamp_unix_ms,
            report.metrics.cpu.as_ref().map(|c| c.global_usage_percent),
            report.metrics.memory.as_ref().map(|m| m.used_bytes),
            report.metrics.disks.len(),
            report.metrics.linux.is_some(),
        );
    }
    Ok(())
}
