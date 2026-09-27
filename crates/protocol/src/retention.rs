//! How long the server keeps each kind of data. The server config's
//! `[retention]` gives the defaults; users can override them at runtime
//! (`GET /retention`, `PUT /retention/{data}`), and reset back to the
//! default.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Longest settable retention (ten years); `0` keeps data forever.
pub const MAX_RETENTION_DAYS: u32 = 3650;

/// A kind of data the server deletes once it's old enough.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionData {
    /// Metrics snapshots, by when the server received them.
    Metrics,
    /// PAM events, by when the server received them.
    AuthEvents,
    /// Resolved alerts, by when they resolved; active ones are always kept.
    Alerts,
}

impl RetentionData {
    pub const ALL: [Self; 3] = [Self::Metrics, Self::AuthEvents, Self::Alerts];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Metrics => "metrics",
            Self::AuthEvents => "auth_events",
            Self::Alerts => "alerts",
        }
    }
}

impl fmt::Display for RetentionData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

impl FromStr for RetentionData {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|d| d.as_str() == s)
            .ok_or_else(|| {
                let names: Vec<_> = Self::ALL.iter().map(|d| d.as_str()).collect();
                format!("unknown data {s:?} (expected one of: {})", names.join(", "))
            })
    }
}

/// Returned by `GET /retention` (one per [`RetentionData`]) and
/// `PUT /retention/{data}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionSetting {
    pub data: RetentionData,
    /// In effect now; `0` = kept forever.
    pub days: u32,
    /// From the server config's `[retention]`, used when not overridden.
    pub default_days: u32,
    /// Set by a user (then `updated_by`/`updated_at` say who and when),
    /// rather than the config default.
    pub overridden: bool,
    pub updated_by: Option<String>,
    /// UTC, `YYYY-MM-DD HH:MM:SS`.
    pub updated_at: Option<String>,
}

/// Sent to `PUT /retention/{data}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetRetention {
    /// `0`-[`MAX_RETENTION_DAYS`], `0` = keep forever. `None`: back to the
    /// config default.
    pub days: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        for data in RetentionData::ALL {
            assert_eq!(data.as_str().parse::<RetentionData>(), Ok(data));
            assert_eq!(serde_json::to_string(&data).unwrap(), format!("\"{data}\""));
        }
        assert!("logs".parse::<RetentionData>().is_err());
    }
}
