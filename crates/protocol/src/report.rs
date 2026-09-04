use serde::{Deserialize, Serialize};

use crate::{MAX_IDENT_LEN, SCHEMA_VERSION, metrics::Metrics};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Report {
    pub schema_version: u16,
    pub host: HostInfo,
    pub timestamp_unix_ms: u64,
    pub metrics: Metrics,
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
        }
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
        Ok(())
    }
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
    use crate::{MAX_IDENT_LEN, Metrics};

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
}
