use protocol::{AgentSummary, ApproveResponse, AuthEventRecord, MetricsRecord};

pub async fn list(client: &reqwest::Client, base: &str) -> Result<(), String> {
    let agents: Vec<AgentSummary> = client
        .get(format!("{base}/agents"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("server error: {e}"))?
        .json()
        .await
        .map_err(|e| format!("invalid response: {e}"))?;

    if agents.is_empty() {
        println!("no agents");
        return Ok(());
    }

    println!(
        "{:<4} {:<9} {:<20} {:<36} {:<20}",
        "ID", "STATUS", "HOSTNAME", "FINGERPRINT", "CREATED_AT"
    );
    for agent in agents {
        println!(
            "{:<4} {:<9} {:<20} {:<36} {:<20}",
            agent.id, agent.status, agent.hostname, agent.fingerprint, agent.created_at
        );
    }
    Ok(())
}

pub async fn approve(client: &reqwest::Client, base: &str, id: i64) -> Result<(), String> {
    let resp: ApproveResponse = client
        .post(format!("{base}/agents/{id}/approve"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("server error: {e}"))?
        .json()
        .await
        .map_err(|e| format!("invalid response: {e}"))?;

    println!("approved agent {id}, token: {}", resp.token);
    Ok(())
}

pub async fn revoke(client: &reqwest::Client, base: &str, id: i64) -> Result<(), String> {
    client
        .post(format!("{base}/agents/{id}/revoke"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("server error: {e}"))?;

    println!("revoked agent {id}");
    Ok(())
}

pub async fn remove(client: &reqwest::Client, base: &str, id: i64) -> Result<(), String> {
    client
        .delete(format!("{base}/agents/{id}"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("server error: {e}"))?;

    println!("removed agent {id}");
    Ok(())
}

pub async fn events(client: &reqwest::Client, base: &str, id: i64) -> Result<(), String> {
    let events: Vec<AuthEventRecord> = client
        .get(format!("{base}/agents/{id}/auth-events"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("server error: {e}"))?
        .json()
        .await
        .map_err(|e| format!("invalid response: {e}"))?;

    if events.is_empty() {
        println!("no events");
        return Ok(());
    }

    println!(
        "{:<20} {:<14} {:<10} {:<12} {:<12} {:<20} {:<10}",
        "OCCURRED_AT", "KIND", "SERVICE", "USER", "RUSER", "RHOST", "TTY"
    );
    for event in events {
        println!(
            "{:<20} {:<14} {:<10} {:<12} {:<12} {:<20} {:<10}",
            event.occurred_at,
            event.kind,
            event.service,
            event.user,
            event.ruser.as_deref().unwrap_or("-"),
            event.rhost.as_deref().unwrap_or("-"),
            event.tty.as_deref().unwrap_or("-"),
        );
    }
    Ok(())
}

pub async fn metrics(
    client: &reqwest::Client,
    base: &str,
    id: i64,
    limit: u32,
) -> Result<(), String> {
    let records: Vec<MetricsRecord> = client
        .get(format!("{base}/agents/{id}/metrics?limit={limit}"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("server error: {e}"))?
        .json()
        .await
        .map_err(|e| format!("invalid response: {e}"))?;

    if records.is_empty() {
        println!("no metrics");
        return Ok(());
    }

    println!(
        "{:<20} {:>6} {:>19} {:>19} {:>16} {:<}",
        "CREATED_AT", "CPU", "MEMORY", "SWAP", "LOAD 1/5/15", "DISKS (used/total)"
    );
    for record in records {
        let m = record.metrics;
        let cpu = m
            .cpu
            .map(|c| format!("{:.1}%", c.global_usage_percent))
            .unwrap_or_else(|| "-".to_string());
        let (memory, swap) = m
            .memory
            .map(|mem| {
                (
                    format!("{}/{}", gib(mem.used_bytes), gib(mem.total_bytes)),
                    format!("{}/{}", gib(mem.swap_used_bytes), gib(mem.swap_total_bytes)),
                )
            })
            .unwrap_or_else(|| ("-".to_string(), "-".to_string()));
        let load = m
            .linux
            .map(|l| {
                format!(
                    "{:.2}/{:.2}/{:.2}",
                    l.load_avg_one, l.load_avg_five, l.load_avg_fifteen
                )
            })
            .unwrap_or_else(|| "-".to_string());
        let disks = m
            .disks
            .iter()
            .map(|d| {
                let used = d.total_bytes.saturating_sub(d.available_bytes);
                format!("{} {}/{}", d.mount_point, gib(used), gib(d.total_bytes))
            })
            .collect::<Vec<_>>()
            .join(", ");

        println!(
            "{:<20} {:>6} {:>19} {:>19} {:>16} {}",
            record.created_at, cpu, memory, swap, load, disks
        );
    }
    Ok(())
}

fn gib(bytes: u64) -> String {
    format!("{:.1}G", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
}
