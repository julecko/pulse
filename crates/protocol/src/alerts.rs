//! Alert rules, the alerts they fire, and the devices alerts are pushed to.
//!
//! A rule compares one [`AlertMetric`] of an agent's metrics snapshots with
//! a threshold. Once the comparison has held for `duration_secs`, the
//! server records an alert (and, if the rule says `notify`, pushes it to
//! every registered device); when it stops holding, the alert is resolved.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A value a rule can watch, computed from each metrics snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertMetric {
    /// Overall CPU usage, 0-100.
    CpuUsagePercent,
    /// Used memory as a share of total, 0-100.
    MemoryUsedPercent,
    /// Used swap as a share of total, 0-100; absent on hosts without swap.
    SwapUsedPercent,
    /// Usage of the fullest disk, 0-100.
    DiskUsedPercent,
    LoadAvgOne,
    LoadAvgFive,
    LoadAvgFifteen,
}

impl AlertMetric {
    pub const ALL: [Self; 7] = [
        Self::CpuUsagePercent,
        Self::MemoryUsedPercent,
        Self::SwapUsedPercent,
        Self::DiskUsedPercent,
        Self::LoadAvgOne,
        Self::LoadAvgFive,
        Self::LoadAvgFifteen,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CpuUsagePercent => "cpu_usage_percent",
            Self::MemoryUsedPercent => "memory_used_percent",
            Self::SwapUsedPercent => "swap_used_percent",
            Self::DiskUsedPercent => "disk_used_percent",
            Self::LoadAvgOne => "load_avg_one",
            Self::LoadAvgFive => "load_avg_five",
            Self::LoadAvgFifteen => "load_avg_fifteen",
        }
    }
}

impl fmt::Display for AlertMetric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

impl FromStr for AlertMetric {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|m| m.as_str() == s)
            .ok_or_else(|| {
                let names: Vec<_> = Self::ALL.iter().map(|m| m.as_str()).collect();
                format!(
                    "unknown metric {s:?} (expected one of: {})",
                    names.join(", ")
                )
            })
    }
}

/// How a rule compares the metric with its threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertOperator {
    #[serde(rename = ">")]
    Gt,
    #[serde(rename = ">=")]
    Ge,
    #[serde(rename = "<")]
    Lt,
    #[serde(rename = "<=")]
    Le,
}

impl AlertOperator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::Lt => "<",
            Self::Le => "<=",
        }
    }

    /// Whether `value <op> threshold` holds.
    pub fn holds(self, value: f64, threshold: f64) -> bool {
        match self {
            Self::Gt => value > threshold,
            Self::Ge => value >= threshold,
            Self::Lt => value < threshold,
            Self::Le => value <= threshold,
        }
    }
}

impl fmt::Display for AlertOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

/// Accepts the symbol (`>`) or, easier to type in a shell, its name (`gt`).
impl FromStr for AlertOperator {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            ">" | "gt" => Ok(Self::Gt),
            ">=" | "ge" => Ok(Self::Ge),
            "<" | "lt" => Ok(Self::Lt),
            "<=" | "le" => Ok(Self::Le),
            _ => Err(format!(
                "unknown operator {s:?} (expected gt, ge, lt, le or >, >=, <, <=)"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Info,
    #[default]
    Warning,
    Critical,
}

impl AlertSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

impl FromStr for AlertSeverity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "info" => Ok(Self::Info),
            "warning" => Ok(Self::Warning),
            "critical" => Ok(Self::Critical),
            _ => Err(format!(
                "unknown severity {s:?} (expected info, warning or critical)"
            )),
        }
    }
}

/// Returned by `GET /alert-rules`, `POST /alert-rules` and
/// `PATCH /alert-rules/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: i64,
    pub name: String,
    /// The agent this rule watches; `None` = every agent.
    pub agent_id: Option<i64>,
    pub metric: AlertMetric,
    pub operator: AlertOperator,
    pub threshold: f64,
    /// How long the condition must hold before the rule fires; 0 = at once.
    pub duration_secs: u32,
    pub severity: AlertSeverity,
    /// Push each alert this rule fires to every registered device.
    pub notify: bool,
    pub enabled: bool,
    pub created_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Sent to `POST /alert-rules`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewAlertRule {
    pub name: String,
    #[serde(default)]
    pub agent_id: Option<i64>,
    pub metric: AlertMetric,
    pub operator: AlertOperator,
    pub threshold: f64,
    #[serde(default)]
    pub duration_secs: u32,
    #[serde(default)]
    pub severity: AlertSeverity,
    #[serde(default)]
    pub notify: bool,
}

/// Sent to `PATCH /alert-rules/{id}`; unset fields stay as they are.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateAlertRule {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub notify: Option<bool>,
}

/// Returned by `GET /alerts`, newest first.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRecord {
    pub id: i64,
    /// `None` once the rule has been deleted.
    pub rule_id: Option<i64>,
    pub agent_id: Option<i64>,
    /// The agent's current hostname, `None` if it's not about one agent.
    pub hostname: Option<String>,
    pub severity: AlertSeverity,
    pub title: String,
    pub message: String,
    /// UTC, `YYYY-MM-DD HH:MM:SS`.
    pub triggered_at: String,
    /// `None` while the condition still holds.
    pub resolved_at: Option<String>,
    pub acknowledged_at: Option<String>,
    pub acknowledged_by: Option<String>,
    /// Set for geo alerts (an SSH login from a country that isn't
    /// allowed), which have no rule; they resolve when acknowledged.
    #[serde(default)]
    pub geo: Option<crate::GeoAlertInfo>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PushPlatform {
    #[default]
    Android,
    Ios,
}

impl PushPlatform {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Android => "android",
            Self::Ios => "ios",
        }
    }
}

impl FromStr for PushPlatform {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "android" => Ok(Self::Android),
            "ios" => Ok(Self::Ios),
            _ => Err(format!("unknown platform {s:?} (expected android or ios)")),
        }
    }
}

/// Sent by the mobile app to `POST /push-devices` (as the logged-in user)
/// to get alert pushes. Registering the same token again updates it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterPushDevice {
    /// FCM registration token.
    pub token: String,
    #[serde(default)]
    pub platform: PushPlatform,
    /// Shown in `devices list`, e.g. "Pixel 8".
    #[serde(default)]
    pub name: Option<String>,
}

/// Returned by `GET /push-devices` and `POST /push-devices`. The token
/// itself is never sent back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushDevice {
    pub id: i64,
    pub username: String,
    pub platform: PushPlatform,
    pub name: Option<String>,
    pub created_at: String,
    pub last_seen_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_names_round_trip() {
        for metric in AlertMetric::ALL {
            assert_eq!(metric.as_str().parse::<AlertMetric>().unwrap(), metric);
            let json = serde_json::to_string(&metric).unwrap();
            assert_eq!(json, format!("\"{}\"", metric.as_str()));
        }
        assert!("cpu".parse::<AlertMetric>().is_err());
    }

    #[test]
    fn operators_parse_and_compare() {
        assert_eq!("gt".parse::<AlertOperator>().unwrap(), AlertOperator::Gt);
        assert_eq!(">=".parse::<AlertOperator>().unwrap(), AlertOperator::Ge);
        assert_eq!(serde_json::to_string(&AlertOperator::Le).unwrap(), "\"<=\"");
        assert!(AlertOperator::Gt.holds(91.0, 90.0));
        assert!(!AlertOperator::Gt.holds(90.0, 90.0));
        assert!(AlertOperator::Ge.holds(90.0, 90.0));
        assert!(AlertOperator::Lt.holds(1.0, 2.0));
        assert!(AlertOperator::Le.holds(2.0, 2.0));
    }
}
