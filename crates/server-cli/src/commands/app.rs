//! `app`: releases of the Android app, which it downloads from the server
//! to update itself.

use std::path::Path;
use std::time::Duration;

use protocol::{AppRelease, NewAppRelease, escape_for_display as esc};
use reqwest::StatusCode;

use super::alerts::{json, send};

/// Longest an upload may take; the server allows 15 minutes.
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(16 * 60);

fn size(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
}

pub async fn list(client: &reqwest::Client, base: &str) -> Result<(), String> {
    let releases: Vec<AppRelease> =
        json(send(client.get(format!("{base}/app-releases"))).await?).await?;
    if releases.is_empty() {
        println!("no app releases uploaded");
        return Ok(());
    }
    println!(
        "{:<12} {:<14} {:<10} {:<24} {:<12} NOTES",
        "CODE", "VERSION", "SIZE", "UPLOADED (UTC)", "BY"
    );
    for (i, r) in releases.iter().enumerate() {
        let notes = r
            .notes
            .as_deref()
            .and_then(|n| n.lines().next())
            .map(|n| esc(n).into_owned())
            .unwrap_or_default();
        println!(
            "{:<12} {:<14} {:<10} {:<24} {:<12} {}{}",
            r.version_code,
            esc(&r.version_name),
            size(r.size),
            esc(&r.created_at),
            esc(r.uploaded_by.as_deref().unwrap_or("-")),
            if i == 0 { "(latest) " } else { "" },
            notes,
        );
    }
    Ok(())
}

pub async fn upload(
    client: &reqwest::Client,
    base: &str,
    apk: &Path,
    version_code: u32,
    version_name: String,
    notes: Option<String>,
    notify: bool,
) -> Result<(), String> {
    let bytes = tokio::fs::read(apk)
        .await
        .map_err(|e| format!("reading {}: {e}", apk.display()))?;
    if !bytes.starts_with(b"PK\x03\x04") {
        return Err(format!("{} isn't an APK (not a ZIP file)", apk.display()));
    }

    // The newest release is what every app installs, so warn before an
    // upload that wouldn't become it (the app never downgrades).
    let latest = client
        .get(format!("{base}/app-releases/latest"))
        .send()
        .await
        .map_err(|e| crate::session::request_error(&e))?;
    if latest.status() != StatusCode::NOT_FOUND {
        let latest: AppRelease =
            json(latest.error_for_status().map_err(|e| e.to_string())?).await?;
        if latest.version_code > version_code {
            eprintln!(
                "warning: release {} ({}) is newer, so apps won't install this one",
                latest.version_code,
                esc(&latest.version_name)
            );
        }
    }

    println!(
        "uploading {} ({})...",
        apk.display(),
        size(bytes.len() as u64)
    );
    let query = NewAppRelease {
        version_name,
        notes,
        notify: Some(notify),
    };
    let release: AppRelease = json(
        send(
            client
                .put(format!("{base}/app-releases/{version_code}"))
                .query(&query)
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/vnd.android.package-archive",
                )
                .timeout(UPLOAD_TIMEOUT)
                .body(bytes),
        )
        .await?,
    )
    .await?;
    println!(
        "uploaded release {} ({}), sha256 {}",
        release.version_code,
        esc(&release.version_name),
        release.sha256
    );
    if notify {
        println!("devices registered for pushes are told about it (if [push] is configured)");
    }
    Ok(())
}

pub async fn remove(client: &reqwest::Client, base: &str, version_code: u32) -> Result<(), String> {
    send(client.delete(format!("{base}/app-releases/{version_code}"))).await?;
    println!("removed app release {version_code}");
    Ok(())
}
