//! Request/response shapes and the API error type.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use protocol::Report;

use crate::store::{Bucket, HostRow, StoreError};

/// Any handler failure. Renders as `{"error": "..."}` with a status code.
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "authentication required".into(),
        }
    }
    pub fn unauthorized_msg(m: &str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: m.into(),
        }
    }
    pub fn bad_request(m: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: m.into(),
        }
    }
    pub fn not_found(m: &str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: m.into(),
        }
    }
    pub fn too_many_requests(m: &str) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: m.into(),
        }
    }
    pub fn internal(e: impl std::fmt::Display) -> Self {
        tracing::error!(error = %e, "api internal error");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal error".into(),
        }
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        ApiError::internal(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

/// Latest metric values for a host, flattened for the list view.
#[derive(Serialize)]
pub struct Snapshot {
    pub ts_ms: u64,
    pub cpu_pct: Option<f32>,
    pub mem_used_bytes: Option<u64>,
    pub mem_total_bytes: Option<u64>,
    pub load1: Option<f64>,
}

impl Snapshot {
    pub fn of(r: &Report) -> Self {
        let m = &r.metrics;
        Self {
            ts_ms: r.timestamp_unix_ms,
            cpu_pct: m.cpu.as_ref().map(|c| c.global_usage_percent),
            mem_used_bytes: m.memory.as_ref().map(|x| x.used_bytes),
            mem_total_bytes: m.memory.as_ref().map(|x| x.total_bytes),
            load1: m.linux.as_ref().map(|x| x.load_avg_one),
        }
    }
}

#[derive(Serialize)]
pub struct HostSummary {
    pub machine_id: String,
    pub hostname: String,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub kernel_version: Option<String>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub last_peer: Option<String>,
    pub report_count: u64,
    pub online: bool,
    pub latest: Option<Snapshot>,
}

impl HostSummary {
    pub fn build(row: HostRow, latest: Option<Snapshot>, now_ms: u64, online_ms: u64) -> Self {
        let online = now_ms.saturating_sub(row.last_seen_ms) <= online_ms;
        Self {
            machine_id: row.machine_id,
            hostname: row.hostname,
            os: row.os,
            os_version: row.os_version,
            kernel_version: row.kernel_version,
            first_seen_ms: row.first_seen_ms,
            last_seen_ms: row.last_seen_ms,
            last_peer: row.last_peer,
            report_count: row.report_count,
            online,
            latest,
        }
    }
}

#[derive(Serialize)]
pub struct HostDetail {
    pub summary: HostSummary,
    pub report: Report,
}

#[derive(Serialize)]
pub struct History {
    pub machine_id: String,
    pub from_ms: u64,
    pub to_ms: u64,
    pub bucket_ms: u64,
    pub buckets: Vec<Bucket>,
}
