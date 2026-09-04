use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{MAX_IDENT_LEN, SCHEMA_VERSION, metrics::Metrics};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Report {
    pub schema_version: u16,
    pub host: HostInfo,
    pub timestamp_unix_ms: u64,
    pub metrics: Metrics,
    /// Typed non-metric observations attached to this report. Keeping these
    /// alongside `metrics` preserves the existing metrics API while allowing
    /// agents to send operational events in the same framed message.
    #[serde(default)]
    pub events: Vec<ReportEvent>,
}

impl Report {
    pub fn new(host: HostInfo, metrics: Metrics) -> Self {
        let timestamp_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            schema_version: SCHEMA_VERSION,
            host,
            timestamp_unix_ms,
            metrics,
            events: Vec::new(),
        }
    }

    pub fn with_events(mut self, events: Vec<ReportEvent>) -> Self {
        self.events = events;
        self
    }

    /// Sanity-check the host identity a peer sent before it is registered,
    /// logged or persisted. `machine_id` is the primary key so it must be
    /// present; every identity string is length- and control-char-bounded so a
    /// hostile peer can't bloat storage or inject into log lines.
    pub fn validate(&self) -> Result<(), &'static str> {
        let h = &self.host;
        if h.machine_id.trim().is_empty() {
            return Err("empty machine_id");
        }
        for (name, value) in [
            ("machine_id", Some(h.machine_id.as_str())),
            ("hostname", Some(h.hostname.as_str())),
            ("os", h.os.as_deref()),
            ("os_version", h.os_version.as_deref()),
            ("kernel_version", h.kernel_version.as_deref()),
        ] {
            let Some(value) = value else { continue };
            if value.len() > MAX_IDENT_LEN {
                return Err(match name {
                    "machine_id" => "machine_id too long",
                    "hostname" => "hostname too long",
                    _ => "host identity field too long",
                });
            }
            if value.contains(|c: char| c.is_control()) {
                return Err(match name {
                    "machine_id" => "machine_id has control characters",
                    "hostname" => "hostname has control characters",
                    _ => "host identity field has control characters",
                });
            }
        }
        for event in &self.events {
            event.validate()?;
        }
        Ok(())
    }
}

/// A non-metric observation carried by a [`Report`].
///
/// Variants are deliberately explicit for data that consumers can act on.
/// `Custom` is the escape hatch for integrations that need a small structured
/// event before a first-class variant exists.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ReportEvent {
    SshLogin(SshLogin),
    Warning(Warning),
    Custom(CustomEvent),
}

impl ReportEvent {
    fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::SshLogin(event) => {
                validate_text("ssh username", &event.username)?;
                validate_text("ssh source", &event.source)?;
                validate_text("ssh auth method", &event.auth_method)?;
            }
            Self::Warning(event) => {
                validate_text("warning code", &event.code)?;
                validate_text("warning message", &event.message)?;
                if let Some(details) = &event.details {
                    validate_text("warning details", details)?;
                }
            }
            Self::Custom(event) => {
                validate_text("custom event name", &event.name)?;
                validate_text("custom event message", &event.message)?;
                for (key, value) in &event.fields {
                    validate_text("custom event field", key)?;
                    validate_text("custom event field", value)?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SshLogin {
    pub username: String,
    pub source: String,
    pub success: bool,
    pub auth_method: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Warning {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub details: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CustomEvent {
    pub name: String,
    pub message: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub fields: BTreeMap<String, String>,
}

fn validate_text(name: &'static str, value: &str) -> Result<(), &'static str> {
    if value.len() > MAX_IDENT_LEN {
        return Err(match name {
            "ssh username" => "ssh username too long",
            "ssh source" => "ssh source too long",
            "ssh auth method" => "ssh auth method too long",
            "warning code" => "warning code too long",
            "warning message" => "warning message too long",
            "warning details" => "warning details too long",
            "custom event name" => "custom event name too long",
            "custom event message" => "custom event message too long",
            _ => "custom event field too long",
        });
    }
    if value.contains(|c: char| c.is_control()) {
        return Err(match name {
            "ssh username" => "ssh username has control characters",
            "ssh source" => "ssh source has control characters",
            "ssh auth method" => "ssh auth method has control characters",
            "warning code" => "warning code has control characters",
            "warning message" => "warning message has control characters",
            "warning details" => "warning details has control characters",
            "custom event name" => "custom event name has control characters",
            "custom event message" => "custom event message has control characters",
            _ => "custom event field has control characters",
        });
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct HostInfo {
    pub machine_id: String,
    pub hostname: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub os_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kernel_version: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CustomEvent, MAX_IDENT_LEN, Metrics, ReportEvent, SshLogin, Warning};

    fn report_with(host: HostInfo) -> Report {
        Report::new(host, Metrics::default())
    }

    #[test]
    fn validate_accepts_a_normal_host() {
        let r = report_with(HostInfo {
            machine_id: "0123456789abcdef".into(),
            hostname: "web-1".into(),
            os: Some("Ubuntu".into()),
            ..Default::default()
        });
        assert!(r.validate().is_ok());
    }

    #[test]
    fn validate_rejects_bad_identity() {
        let empty = report_with(HostInfo {
            machine_id: "  ".into(),
            hostname: "h".into(),
            ..Default::default()
        });
        assert_eq!(empty.validate(), Err("empty machine_id"));

        let long = report_with(HostInfo {
            machine_id: "m".into(),
            hostname: "h".repeat(MAX_IDENT_LEN + 1),
            ..Default::default()
        });
        assert_eq!(long.validate(), Err("hostname too long"));

        let ctrl = report_with(HostInfo {
            machine_id: "m".into(),
            hostname: "line1\nFAKE LOG".into(),
            ..Default::default()
        });
        assert_eq!(ctrl.validate(), Err("hostname has control characters"));
    }

    #[test]
    fn report_supports_typed_events() {
        let report = report_with(HostInfo {
            machine_id: "m".into(),
            hostname: "h".into(),
            ..Default::default()
        })
        .with_events(vec![
            ReportEvent::SshLogin(SshLogin {
                username: "alice".into(),
                source: "192.0.2.10".into(),
                success: true,
                auth_method: "publickey".into(),
            }),
            ReportEvent::Warning(Warning {
                code: "disk-nearly-full".into(),
                message: "Less than 10% space remains".into(),
                details: None,
            }),
            ReportEvent::Custom(CustomEvent {
                name: "deployment".into(),
                message: "version changed".into(),
                fields: [("version".into(), "1.2.3".into())].into_iter().collect(),
            }),
        ]);

        assert!(report.validate().is_ok());
        let decoded = crate::decode_body(&crate::encode_body(&report).unwrap()).unwrap();
        assert_eq!(decoded.events, report.events);
    }
}
