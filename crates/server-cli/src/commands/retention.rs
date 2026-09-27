//! `retention`: how long the server keeps metrics, PAM events and resolved
//! alerts.

use protocol::{RetentionData, RetentionSetting, SetRetention, escape_for_display as esc};

use super::alerts::{json, send};

fn days(days: u32) -> String {
    match days {
        0 => "forever".to_string(),
        1 => "1 day".to_string(),
        n => format!("{n} days"),
    }
}

async fn get_all(client: &reqwest::Client, base: &str) -> Result<Vec<RetentionSetting>, String> {
    json(send(client.get(format!("{base}/retention"))).await?).await
}

pub async fn show(client: &reqwest::Client, base: &str) -> Result<(), String> {
    let settings = get_all(client, base).await?;
    println!(
        "{:<12} {:<12} {:<12} {:<}",
        "DATA", "KEPT", "DEFAULT", "SET BY"
    );
    for s in settings {
        let set_by = match (&s.updated_by, &s.updated_at) {
            (Some(by), Some(at)) => format!("{} at {} UTC", esc(by), esc(at)),
            _ if s.overridden => "?".to_string(),
            _ => "- (config default)".to_string(),
        };
        println!(
            "{:<12} {:<12} {:<12} {:<}",
            s.data,
            days(s.days),
            days(s.default_days),
            set_by
        );
    }
    Ok(())
}

/// Sets (`Some`) or resets (`None`) `data`'s retention, saying what
/// changed and whether older rows are being deleted.
pub async fn set(
    client: &reqwest::Client,
    base: &str,
    data: RetentionData,
    new_days: Option<u32>,
) -> Result<(), String> {
    let before = get_all(client, base)
        .await?
        .into_iter()
        .find(|s| s.data == data)
        .map(|s| s.days);

    let after: RetentionSetting = json(
        send(
            client
                .put(format!("{base}/retention/{data}"))
                .json(&SetRetention { days: new_days }),
        )
        .await?,
    )
    .await?;

    let source = if after.overridden {
        ""
    } else {
        " (the server config's default)"
    };
    match before {
        Some(before) if before != after.days => println!(
            "{data}: kept {}{source}, was {}",
            days(after.days),
            days(before)
        ),
        _ => println!("{data}: kept {}{source}", days(after.days)),
    }
    let shorter = match before {
        Some(0) => after.days > 0,
        Some(before) => after.days > 0 && after.days < before,
        None => false,
    };
    if shorter {
        println!("older {data} are being deleted now");
    }
    Ok(())
}
