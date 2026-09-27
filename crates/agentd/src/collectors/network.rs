use std::error::Error;
use std::time::Instant;

use protocol::{Metrics, NetworkInfo, NetworkInterfaceInfo};

use super::{Collector, Context};

pub struct NetworkCollector;

impl Collector for NetworkCollector {
    fn name(&self) -> &'static str {
        "network"
    }

    fn collect_into(
        &mut self,
        ctx: &mut Context,
        metrics: &mut Metrics,
    ) -> Result<(), Box<dyn Error>> {
        // sysinfo reports bytes since the previous refresh, and `ctx` lives
        // across collections, so dividing by the time since then gives the
        // average rate over the whole interval.
        ctx.networks.refresh(true);
        let now = Instant::now();
        let elapsed = now.duration_since(ctx.networks_refreshed_at).as_secs_f64();
        ctx.networks_refreshed_at = now;
        if elapsed <= 0.0 {
            return Ok(());
        }

        let mut interfaces: Vec<NetworkInterfaceInfo> = ctx
            .networks
            .list()
            .iter()
            .filter(|(name, _)| !is_virtual(name))
            .map(|(name, data)| NetworkInterfaceInfo {
                name: name.clone(),
                rx_bytes_per_sec: data.received() as f64 / elapsed,
                tx_bytes_per_sec: data.transmitted() as f64 / elapsed,
                total_rx_bytes: data.total_received(),
                total_tx_bytes: data.total_transmitted(),
            })
            .collect();
        interfaces.sort_by(|a, b| a.name.cmp(&b.name));

        metrics.network = Some(NetworkInfo {
            rx_bytes_per_sec: interfaces.iter().map(|i| i.rx_bytes_per_sec).sum(),
            tx_bytes_per_sec: interfaces.iter().map(|i| i.tx_bytes_per_sec).sum(),
            interfaces,
        });
        Ok(())
    }
}

/// Loopback and the virtual interfaces containers and VMs hang off: their
/// traffic stays on the host or also crosses a real interface, so counting
/// it would double the total.
fn is_virtual(name: &str) -> bool {
    const PREFIXES: [&str; 9] = [
        "veth", "docker", "br-", "virbr", "vnet", "cni", "flannel", "cali", "lxc",
    ];
    name == "lo" || PREFIXES.iter().any(|p| name.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_loopback_and_virtual_interfaces() {
        for name in [
            "lo",
            "veth1a2b3c",
            "docker0",
            "br-0123abcd",
            "virbr0",
            "cni0",
        ] {
            assert!(is_virtual(name), "{name}");
        }
        for name in ["eth0", "enp3s0", "wlan0", "wg0", "bond0", "vmbr0"] {
            assert!(!is_virtual(name), "{name}");
        }
    }
}
