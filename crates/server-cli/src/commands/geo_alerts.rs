//! `geo-alerts`: alert when an SSH login comes from a country that isn't
//! allowed (looked up in the server's GeoIP database).

use protocol::{GeoAlertSettings, SetGeoAlertSettings, escape_for_display as esc};

use super::alerts::{json, send};

async fn get(client: &reqwest::Client, base: &str) -> Result<GeoAlertSettings, String> {
    json(send(client.get(format!("{base}/geo-alerts/settings"))).await?).await
}

pub async fn show(client: &reqwest::Client, base: &str) -> Result<(), String> {
    print(&get(client, base).await?);
    Ok(())
}

/// Replaces the settings; empty `countries` turns geo alerts off.
pub async fn set(
    client: &reqwest::Client,
    base: &str,
    countries: Vec<String>,
    include_failures: bool,
    notify: bool,
) -> Result<(), String> {
    let settings: GeoAlertSettings = json(
        send(
            client
                .put(format!("{base}/geo-alerts/settings"))
                .json(&SetGeoAlertSettings {
                    allowed_countries: countries,
                    include_failures,
                    notify,
                }),
        )
        .await?,
    )
    .await?;
    print(&settings);
    Ok(())
}

/// Turns geo alerts off, keeping the other settings for next time.
pub async fn off(client: &reqwest::Client, base: &str) -> Result<(), String> {
    let current = get(client, base).await?;
    set(
        client,
        base,
        Vec::new(),
        current.include_failures,
        current.notify,
    )
    .await
}

fn print(s: &GeoAlertSettings) {
    if s.allowed_countries.is_empty() {
        println!("geo alerts: off");
    } else {
        println!(
            "geo alerts: on; SSH logins allowed from {}",
            s.allowed_countries.join(", ")
        );
        println!(
            "  alert on: successful logins{}",
            if s.include_failures {
                " and failed ones"
            } else {
                " (not failed ones)"
            }
        );
        println!(
            "  pushed: {}",
            if s.notify {
                "yes"
            } else {
                "no (recorded only)"
            }
        );
    }
    let by = s.updated_by.as_deref().map(esc).unwrap_or("-".into());
    println!("last changed {} UTC by {by}", s.updated_at);
    match &s.database {
        Some(db) => println!(
            "GeoIP database: {} ({}, built {} UTC)",
            esc(&db.path),
            esc(&db.database_type),
            db.built_at
        ),
        None if s.allowed_countries.is_empty() => {
            println!("GeoIP database: none loaded on the server")
        }
        None => println!(
            "WARNING: the server has no GeoIP database loaded, so no geo alerts fire; \
             put GeoLite2-City.mmdb where [geoip] database points and restart it"
        ),
    }
}
