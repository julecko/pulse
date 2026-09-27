//! Geo alerts: an alert when an SSH login to an agent comes from an IP
//! outside the allowed countries (settings: `web::geo_alerts`).
//!
//! Checked for every PAM event an agent reports (see
//! `web::auth_events::ingest`) that is:
//! - from `sshd`, with the client's IP as `rhost` (sshd's default; with
//!   `UseDNS yes` it's a hostname, which is skipped)
//! - a successful login (`session_open`), or a failed one (`auth_failure`)
//!   if the settings include failures
//! - from a public IP (see [`crate::geoip::is_public`]): LAN and VPN logins
//!   have no country
//!
//! If the IP's country isn't allowed, or the database doesn't know the IP
//! (so it can't be shown to be allowed), an alert is recorded: a normal
//! `alerts` row (no rule) plus its details in `geo_alerts`, and pushed if
//! the settings say so. A successful login is `critical`, a failure
//! `warning`. At most one geo alert per agent, IP and kind is active at a
//! time, so repeated logins (or a brute force) from one address raise one
//! alert until it's acknowledged, which also resolves it.

use std::net::IpAddr;
use std::path::Path;

use protocol::{AlertSeverity, AuthEvent, AuthEventKind, escape_for_display};
use sqlx::SqlitePool;

use crate::geoip::{self, GeoIp, Location};
use crate::push::{Push, PushMessage};
use crate::web::RateLimiter;

/// Longest user name shown in an alert; for failed logins it's whatever the
/// client sent.
const MAX_USER_CHARS: usize = 64;

pub struct GeoAlerts {
    geoip: GeoIp,
}

/// `geo_alert_settings`, parsed.
struct Settings {
    allowed_countries: Vec<String>,
    include_failures: bool,
    notify: bool,
}

impl GeoAlerts {
    pub fn new(geoip: GeoIp) -> Self {
        Self { geoip }
    }

    /// The client IP of a PAM event's `rhost` and where it is, if it's a
    /// public IP and a database is loaded. Looked up once per event, for
    /// both storing it and [`Self::evaluate`].
    pub fn locate(&self, rhost: Option<&str>) -> Option<(IpAddr, Location)> {
        let ip = client_ip(rhost?)?;
        Some((ip, self.geoip.lookup(ip)?))
    }

    /// See [`GeoIp::database`].
    pub fn database(&self) -> Option<(&Path, &str, u64)> {
        self.geoip.database()
    }

    /// Checks one stored PAM event (see the module docs), `located` by
    /// [`Self::locate`]. Errors are logged, never returned: they mustn't
    /// fail the ingest. `limiter` is the agent's push budget, shared with
    /// its other pushes.
    pub async fn evaluate(
        &self,
        pool: &SqlitePool,
        push: &Push,
        limiter: Option<&RateLimiter<i64>>,
        agent_id: i64,
        event: &AuthEvent,
        located: Option<&(IpAddr, Location)>,
    ) {
        if let Err(err) = self
            .evaluate_inner(pool, push, limiter, agent_id, event, located)
            .await
        {
            tracing::warn!(%err, agent_id, "geo alert check failed");
        }
    }

    async fn evaluate_inner(
        &self,
        pool: &SqlitePool,
        push: &Push,
        limiter: Option<&RateLimiter<i64>>,
        agent_id: i64,
        event: &AuthEvent,
        located: Option<&(IpAddr, Location)>,
    ) -> Result<(), sqlx::Error> {
        if event.service != "sshd"
            || !matches!(
                event.kind,
                AuthEventKind::SessionOpen | AuthEventKind::AuthFailure
            )
        {
            return Ok(());
        }
        // Not a public IP, or no database.
        let Some((ip, location)) = located else {
            return Ok(());
        };
        let settings = load_settings(pool).await?;
        if settings.allowed_countries.is_empty()
            || (event.kind == AuthEventKind::AuthFailure && !settings.include_failures)
        {
            return Ok(());
        }
        if location
            .country_code
            .as_ref()
            .is_some_and(|code| settings.allowed_countries.contains(code))
        {
            return Ok(());
        }

        let ip_str = ip.to_string();
        let active: Option<i64> = sqlx::query_scalar(
            "SELECT a.id FROM alerts a JOIN geo_alerts g ON g.alert_id = a.id
             WHERE a.agent_id = ? AND g.ip = ? AND g.kind = ? AND a.resolved_at IS NULL",
        )
        .bind(agent_id)
        .bind(&ip_str)
        .bind(event.kind.as_str())
        .fetch_optional(pool)
        .await?;
        if active.is_some() {
            return Ok(());
        }

        let hostname: Option<String> =
            sqlx::query_scalar("SELECT hostname FROM agents WHERE id = ?")
                .bind(agent_id)
                .fetch_optional(pool)
                .await?;
        let (severity, title, message) = alert_text(
            hostname.as_deref().unwrap_or("unknown host"),
            event,
            &ip_str,
            location,
        );

        let mut tx = pool.begin().await?;
        let alert_id: i64 = sqlx::query_scalar(
            "INSERT INTO alerts (agent_id, severity, title, message) VALUES (?, ?, ?, ?)
             RETURNING id",
        )
        .bind(agent_id)
        .bind(severity.as_str())
        .bind(&title)
        .bind(&message)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO geo_alerts (alert_id, kind, ip, user, country_code, country_name, city)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(alert_id)
        .bind(event.kind.as_str())
        .bind(&ip_str)
        .bind(short(&event.user))
        .bind(&location.country_code)
        .bind(&location.country_name)
        .bind(&location.city)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        tracing::warn!(
            alert_id,
            agent_id,
            ip = %ip_str,
            country = location.country_code.as_deref().unwrap_or("unknown"),
            kind = event.kind.as_str(),
            "geo alert: SSH from a country that isn't allowed"
        );

        if !settings.notify {
            return Ok(());
        }
        if let Some(limiter) = limiter
            && limiter.check(agent_id, std::time::Instant::now()).is_err()
        {
            tracing::warn!(
                alert_id,
                agent_id,
                "geo alert not pushed: agent over its push limit"
            );
            return Ok(());
        }
        push.notify_all(
            pool,
            PushMessage::alert(alert_id, agent_id, severity.as_str(), title, message),
        );
        Ok(())
    }
}

/// The client's IP from `rhost`, if it's a public one.
fn client_ip(rhost: &str) -> Option<IpAddr> {
    let ip: IpAddr = rhost.trim().parse().ok()?;
    let ip = ip.to_canonical();
    geoip::is_public(ip).then_some(ip)
}

async fn load_settings(pool: &SqlitePool) -> Result<Settings, sqlx::Error> {
    let (allowed, include_failures, notify): (String, bool, bool) = sqlx::query_as(
        "SELECT allowed_countries, include_failures, notify FROM geo_alert_settings WHERE id = 1",
    )
    .fetch_one(pool)
    .await?;
    Ok(Settings {
        allowed_countries: allowed
            .split(',')
            .filter(|c| !c.is_empty())
            .map(str::to_string)
            .collect(),
        include_failures,
        notify,
    })
}

/// `s` escaped (see [`escape_for_display`]) and cut to [`MAX_USER_CHARS`].
fn short(s: &str) -> String {
    let escaped = escape_for_display(s);
    if escaped.chars().count() <= MAX_USER_CHARS {
        return escaped.into_owned();
    }
    let mut cut: String = escaped.chars().take(MAX_USER_CHARS - 1).collect();
    cut.push('…');
    cut
}

/// Severity, title and message, e.g. `critical`, "SSH login from Russia
/// (RU) on web01", "root from 203.0.113.9 (Moscow)".
fn alert_text(
    hostname: &str,
    event: &AuthEvent,
    ip: &str,
    location: &Location,
) -> (AlertSeverity, String, String) {
    let country = match (&location.country_name, &location.country_code) {
        (Some(name), Some(code)) => format!("{name} ({code})"),
        (None, Some(code)) => code.clone(),
        _ => "an unknown country".to_string(),
    };
    let (severity, what) = match event.kind {
        AuthEventKind::AuthFailure => (AlertSeverity::Warning, "Failed SSH login"),
        _ => (AlertSeverity::Critical, "SSH login"),
    };
    let title = format!("{what} from {country} on {hostname}");
    let place = location
        .city
        .as_deref()
        .map(|city| format!(" ({city})"))
        .unwrap_or_default();
    let message = format!("{} from {ip}{place}", short(&event.user));
    (severity, title, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: AuthEventKind, user: &str, rhost: Option<&str>) -> AuthEvent {
        AuthEvent {
            kind,
            service: "sshd".to_string(),
            user: user.to_string(),
            ruser: None,
            rhost: rhost.map(str::to_string),
            tty: None,
            occurred_at: 0,
        }
    }

    #[test]
    fn only_public_ips_are_checked() {
        assert_eq!(
            client_ip("81.2.69.142"),
            Some("81.2.69.142".parse().unwrap())
        );
        assert_eq!(
            client_ip("::ffff:81.2.69.142"),
            Some("81.2.69.142".parse().unwrap())
        );
        assert_eq!(client_ip("192.168.1.5"), None);
        assert_eq!(client_ip("host.example.com"), None); // UseDNS yes
    }

    #[test]
    fn alert_text_for_login_and_failure() {
        let moscow = Location {
            country_code: Some("RU".into()),
            country_name: Some("Russia".into()),
            city: Some("Moscow".into()),
        };
        let (severity, title, message) = alert_text(
            "web01",
            &event(AuthEventKind::SessionOpen, "root", None),
            "203.0.113.9",
            &moscow,
        );
        assert_eq!(severity, AlertSeverity::Critical);
        assert_eq!(title, "SSH login from Russia (RU) on web01");
        assert_eq!(message, "root from 203.0.113.9 (Moscow)");

        let (severity, title, message) = alert_text(
            "web01",
            &event(AuthEventKind::AuthFailure, "adm\x1bin", None),
            "203.0.113.9",
            &Location::default(),
        );
        assert_eq!(severity, AlertSeverity::Warning);
        assert_eq!(title, "Failed SSH login from an unknown country on web01");
        assert_eq!(message, "adm\\x1bin from 203.0.113.9");
    }
}
