//! `rules`, `alerts` and `devices`: alert rules, the alerts they fire, and
//! the devices alerts are pushed to.

use protocol::{
    AlertRecord, AlertRule, NewAlertRule, PushDevice, UpdateAlertRule, escape_for_display as esc,
};

/// Sends `req`; on a non-success status, fails with the server's message
/// (it says e.g. which field of a new rule is wrong).
pub(super) async fn send(req: reqwest::RequestBuilder) -> Result<reqwest::Response, String> {
    let resp = req
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().await.unwrap_or_default();
    Err(format!("server error ({status}): {}", esc(&body)))
}

pub(super) async fn json<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T, String> {
    resp.json()
        .await
        .map_err(|e| format!("invalid response: {e}"))
}

fn on_off(b: bool) -> &'static str {
    if b { "on" } else { "off" }
}

pub async fn list_rules(client: &reqwest::Client, base: &str) -> Result<(), String> {
    let rules: Vec<AlertRule> =
        json(send(client.get(format!("{base}/alert-rules"))).await?).await?;
    if rules.is_empty() {
        println!("no alert rules");
        return Ok(());
    }

    println!(
        "{:<4} {:<24} {:<6} {:<40} {:<8} {:<9} {:<6} {:<7}",
        "ID", "NAME", "AGENT", "CONDITION", "FOR", "SEVERITY", "NOTIFY", "ENABLED"
    );
    for rule in rules {
        let agent = rule
            .agent_id
            .map_or_else(|| "all".to_string(), |id| id.to_string());
        let condition = format!("{} {} {}", rule.metric, rule.operator, rule.threshold);
        let duration = if rule.duration_secs == 0 {
            "-".to_string()
        } else {
            human_duration(rule.duration_secs)
        };
        println!(
            "{:<4} {:<24} {:<6} {:<40} {:<8} {:<9} {:<6} {:<7}",
            rule.id,
            esc(&rule.name),
            agent,
            condition,
            duration,
            rule.severity,
            on_off(rule.notify),
            if rule.enabled { "yes" } else { "no" },
        );
    }
    Ok(())
}

pub async fn add_rule(
    client: &reqwest::Client,
    base: &str,
    rule: &NewAlertRule,
) -> Result<(), String> {
    let rule: AlertRule =
        json(send(client.post(format!("{base}/alert-rules")).json(rule)).await?).await?;
    println!(
        "added rule {}: {} {} {}{}, severity {}, notify {}",
        rule.id,
        rule.metric,
        rule.operator,
        rule.threshold,
        if rule.duration_secs > 0 {
            format!(" for {}", human_duration(rule.duration_secs))
        } else {
            String::new()
        },
        rule.severity,
        on_off(rule.notify),
    );
    Ok(())
}

pub async fn update_rule(
    client: &reqwest::Client,
    base: &str,
    id: i64,
    enabled: Option<bool>,
    notify: Option<bool>,
) -> Result<(), String> {
    let update = UpdateAlertRule { enabled, notify };
    let rule: AlertRule = json(
        send(
            client
                .patch(format!("{base}/alert-rules/{id}"))
                .json(&update),
        )
        .await?,
    )
    .await?;
    println!(
        "rule {}: {}, notify {}",
        rule.id,
        if rule.enabled { "enabled" } else { "disabled" },
        on_off(rule.notify)
    );
    Ok(())
}

pub async fn remove_rule(client: &reqwest::Client, base: &str, id: i64) -> Result<(), String> {
    send(client.delete(format!("{base}/alert-rules/{id}"))).await?;
    println!("removed rule {id}");
    Ok(())
}

pub async fn list_alerts(
    client: &reqwest::Client,
    base: &str,
    agent: Option<i64>,
    active: bool,
    limit: u32,
) -> Result<(), String> {
    let mut query = vec![("limit", limit.to_string())];
    if let Some(agent) = agent {
        query.push(("agent_id", agent.to_string()));
    }
    if active {
        query.push(("active", "true".to_string()));
    }
    let alerts: Vec<AlertRecord> =
        json(send(client.get(format!("{base}/alerts")).query(&query)).await?).await?;
    if alerts.is_empty() {
        println!("no alerts");
        return Ok(());
    }

    println!(
        "{:<5} {:<20} {:<9} {:<20} {:<6} {:<30} {:<}",
        "ID", "TRIGGERED_AT", "SEVERITY", "STATE", "AGENT", "TITLE", "MESSAGE"
    );
    for alert in alerts {
        let state = match (&alert.resolved_at, &alert.acknowledged_by) {
            (Some(at), _) => format!("resolved {}", &at[at.len().saturating_sub(8)..]),
            (None, Some(by)) => format!("active, ack by {by}"),
            (None, None) => "ACTIVE".to_string(),
        };
        let agent = alert
            .agent_id
            .map_or_else(|| "-".to_string(), |id| id.to_string());
        println!(
            "{:<5} {:<20} {:<9} {:<20} {:<6} {:<30} {:<}",
            alert.id,
            esc(&alert.triggered_at),
            alert.severity,
            esc(&state),
            agent,
            esc(&alert.title),
            esc(&alert.message),
        );
    }
    Ok(())
}

pub async fn acknowledge(client: &reqwest::Client, base: &str, id: i64) -> Result<(), String> {
    send(client.post(format!("{base}/alerts/{id}/acknowledge"))).await?;
    println!("acknowledged alert {id}");
    Ok(())
}

pub async fn list_devices(client: &reqwest::Client, base: &str) -> Result<(), String> {
    let devices: Vec<PushDevice> =
        json(send(client.get(format!("{base}/push-devices"))).await?).await?;
    if devices.is_empty() {
        println!("no devices (the mobile app registers them)");
        return Ok(());
    }

    println!(
        "{:<4} {:<16} {:<8} {:<24} {:<20} {:<20}",
        "ID", "USER", "PLATFORM", "NAME", "REGISTERED_AT", "LAST_SEEN_AT"
    );
    for device in devices {
        println!(
            "{:<4} {:<16} {:<8} {:<24} {:<20} {:<20}",
            device.id,
            esc(&device.username),
            device.platform.as_str(),
            esc(device.name.as_deref().unwrap_or("-")),
            esc(&device.created_at),
            esc(&device.last_seen_at),
        );
    }
    Ok(())
}

pub async fn remove_device(client: &reqwest::Client, base: &str, id: i64) -> Result<(), String> {
    send(client.delete(format!("{base}/push-devices/{id}"))).await?;
    println!("removed device {id}");
    Ok(())
}

/// `300` -> `5m`, `7200` -> `2h`, `90` -> `90s`.
fn human_duration(secs: u32) -> String {
    if secs >= 3600 && secs.is_multiple_of(3600) {
        format!("{}h", secs / 3600)
    } else if secs >= 60 && secs.is_multiple_of(60) {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}
