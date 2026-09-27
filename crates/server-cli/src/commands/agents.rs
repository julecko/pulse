use protocol::{
    AgentSummary, AuthEventKind, AuthEventRecord, MetricsRecord, OfflineAlertSetting,
    PairingStatus, PamNotifications, SetOfflineAlert, SetPairingRequest, SetPamNotifications,
    escape_for_display as esc,
};

use super::alerts::{json, send};

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
            agent.id,
            esc(&agent.status),
            esc(&agent.hostname),
            esc(&agent.fingerprint),
            esc(&agent.created_at)
        );
    }
    Ok(())
}

pub async fn approve(client: &reqwest::Client, base: &str, id: i64) -> Result<(), String> {
    let resp = client
        .post(format!("{base}/agents/{id}/approve"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        // The body explains e.g. why a revoked agent can't be re-approved.
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("server error ({status}): {body}"));
    }

    println!("approved agent {id}");
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

pub async fn unrevoke(client: &reqwest::Client, base: &str, id: i64) -> Result<(), String> {
    let resp = client
        .post(format!("{base}/agents/{id}/unrevoke"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("server error ({status}): {body}"));
    }

    println!("unrevoked agent {id}; it resumes on its next pairing poll (within a minute)");
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
        "{:<20} {:<14} {:<10} {:<12} {:<12} {:<20} {:<10} {:<}",
        "OCCURRED_AT", "KIND", "SERVICE", "USER", "RUSER", "RHOST", "TTY", "LOCATION"
    );
    for event in events {
        let location = match (&event.city, &event.country_code) {
            (Some(city), Some(code)) => format!("{city}, {code}"),
            (None, Some(code)) => event.country_name.clone().unwrap_or_else(|| code.clone()),
            _ => "-".to_string(),
        };
        println!(
            "{:<20} {:<14} {:<10} {:<12} {:<12} {:<20} {:<10} {:<}",
            esc(&event.occurred_at),
            esc(&event.kind),
            esc(&event.service),
            esc(&event.user),
            esc(event.ruser.as_deref().unwrap_or("-")),
            esc(event.rhost.as_deref().unwrap_or("-")),
            esc(event.tty.as_deref().unwrap_or("-")),
            esc(&location),
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
        "{:<20} {:>6} {:>19} {:>19} {:>16} {:>21} {:<}",
        "CREATED_AT", "CPU", "MEMORY", "SWAP", "LOAD 1/5/15", "NET RX/TX", "DISKS (used/total)"
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
        let net = m
            .network
            .map(|n| format!("{}/{}", rate(n.rx_bytes_per_sec), rate(n.tx_bytes_per_sec)))
            .unwrap_or_else(|| "-".to_string());
        let disks = m
            .disks
            .iter()
            .map(|d| {
                let used = d.total_bytes.saturating_sub(d.available_bytes);
                format!(
                    "{} {}/{}",
                    esc(&d.mount_point),
                    gib(used),
                    gib(d.total_bytes)
                )
            })
            .collect::<Vec<_>>()
            .join(", ");

        println!(
            "{:<20} {:>6} {:>19} {:>19} {:>16} {:>21} {}",
            esc(&record.created_at),
            cpu,
            memory,
            swap,
            load,
            net,
            disks
        );
    }
    Ok(())
}

fn gib(bytes: u64) -> String {
    format!("{:.1}G", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
}

/// Bytes per second as `1.2M/s` (binary units, like [`gib`]).
fn rate(bytes_per_sec: f64) -> String {
    const UNITS: [&str; 4] = ["B", "K", "M", "G"];
    let mut v = bytes_per_sec;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    format!("{v:.1}{}/s", UNITS[unit])
}

pub async fn pairing_status(client: &reqwest::Client, base: &str) -> Result<(), String> {
    let status: PairingStatus = client
        .get(format!("{base}/agents/pairing"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("server error: {e}"))?
        .json()
        .await
        .map_err(|e| format!("invalid response: {e}"))?;
    print_pairing(&status);
    Ok(())
}

pub async fn set_pairing(
    client: &reqwest::Client,
    base: &str,
    open: bool,
    minutes: Option<u32>,
) -> Result<(), String> {
    let status: PairingStatus = client
        .put(format!("{base}/agents/pairing"))
        .json(&SetPairingRequest { open, minutes })
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?
        .error_for_status()
        .map_err(|e| format!("server error: {e}"))?
        .json()
        .await
        .map_err(|e| format!("invalid response: {e}"))?;
    print_pairing(&status);
    Ok(())
}

fn print_pairing(status: &PairingStatus) {
    let state = match (status.open, &status.open_until) {
        (true, Some(until)) => format!("open until {until} UTC"),
        (true, None) => "open (until closed)".to_string(),
        (false, _) => "closed".to_string(),
    };
    let by = status.updated_by.as_deref().unwrap_or("-");
    println!("pairing: {state}");
    println!("last changed {} UTC by {by}", status.updated_at);
    if status.open {
        println!("new agents can send pairing requests; approve them with `agents approve <id>`");
    }
}

fn pam_kinds(settings: &PamNotifications) -> String {
    if settings.kinds.is_empty() {
        return "off".to_string();
    }
    settings
        .kinds
        .iter()
        .map(|k| k.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Every agent's PAM push settings.
pub async fn pam_notify_list(client: &reqwest::Client, base: &str) -> Result<(), String> {
    let all: Vec<PamNotifications> =
        json(send(client.get(format!("{base}/agents/pam-notifications"))).await?).await?;
    if all.is_empty() {
        println!("no agents");
        return Ok(());
    }
    println!("{:<4} {:<20} {:<}", "ID", "HOSTNAME", "PUSHED PAM EVENTS");
    for settings in all {
        println!(
            "{:<4} {:<20} {:<}",
            settings.agent_id,
            esc(&settings.hostname),
            pam_kinds(&settings)
        );
    }
    Ok(())
}

pub async fn pam_notify_show(client: &reqwest::Client, base: &str, id: i64) -> Result<(), String> {
    let settings: PamNotifications =
        json(send(client.get(format!("{base}/agents/{id}/pam-notifications"))).await?).await?;
    print_pam_notify(&settings);
    Ok(())
}

/// Replaces agent `id`'s pushed PAM event kinds; empty turns them off.
pub async fn pam_notify_set(
    client: &reqwest::Client,
    base: &str,
    id: i64,
    kinds: Vec<AuthEventKind>,
) -> Result<(), String> {
    let settings: PamNotifications = json(
        send(
            client
                .put(format!("{base}/agents/{id}/pam-notifications"))
                .json(&SetPamNotifications { kinds }),
        )
        .await?,
    )
    .await?;
    print_pam_notify(&settings);
    Ok(())
}

fn print_pam_notify(settings: &PamNotifications) {
    println!(
        "agent {} ({}): pushed PAM events: {}",
        settings.agent_id,
        esc(&settings.hostname),
        pam_kinds(settings)
    );
}

fn duration(secs: u32) -> String {
    match secs {
        s if s % 86400 == 0 => format!("{}d", s / 86400),
        s if s % 3600 == 0 => format!("{}h", s / 3600),
        s if s % 60 == 0 => format!("{}m", s / 60),
        s => format!("{s}s"),
    }
}

fn offline_state(s: &OfflineAlertSetting) -> &'static str {
    match (s.after_secs, s.offline, s.status.as_str()) {
        (None, _, _) => "-",
        (Some(_), true, _) => "OFFLINE",
        (Some(_), false, "approved") => "ok",
        (Some(_), false, _) => "not approved",
    }
}

/// Every agent's offline alert limit and state.
pub async fn offline_alert_list(client: &reqwest::Client, base: &str) -> Result<(), String> {
    let all: Vec<OfflineAlertSetting> =
        json(send(client.get(format!("{base}/agents/offline-alerts"))).await?).await?;
    if all.is_empty() {
        println!("no agents");
        return Ok(());
    }
    println!(
        "{:<4} {:<20} {:<10} {:<13} {:<20} {:<}",
        "ID", "HOSTNAME", "STATUS", "ALERT AFTER", "LAST METRICS (UTC)", "STATE"
    );
    for s in all {
        println!(
            "{:<4} {:<20} {:<10} {:<13} {:<20} {:<}",
            s.agent_id,
            esc(&s.hostname),
            esc(&s.status),
            s.after_secs.map_or_else(|| "off".to_string(), duration),
            s.last_metrics_at
                .as_deref()
                .map_or_else(|| "never".into(), esc),
            offline_state(&s)
        );
    }
    Ok(())
}

/// Sets (`Some`) or turns off (`None`) agent `id`'s offline alert.
pub async fn offline_alert_set(
    client: &reqwest::Client,
    base: &str,
    id: i64,
    after_secs: Option<u32>,
) -> Result<(), String> {
    let s: OfflineAlertSetting = json(
        send(
            client
                .put(format!("{base}/agents/{id}/offline-alert"))
                .json(&SetOfflineAlert { after_secs }),
        )
        .await?,
    )
    .await?;
    match s.after_secs {
        Some(secs) => {
            println!(
                "agent {} ({}): alert after {} without metrics",
                s.agent_id,
                esc(&s.hostname),
                duration(secs)
            );
            if s.status != "approved" {
                println!(
                    "note: it's {}; only approved agents are watched",
                    esc(&s.status)
                );
            }
        }
        None => println!(
            "agent {} ({}): offline alert off",
            s.agent_id,
            esc(&s.hostname)
        ),
    }
    Ok(())
}
