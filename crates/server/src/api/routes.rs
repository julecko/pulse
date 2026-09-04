//! Router + request handlers.

use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::{get, post};
use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;

use protocol::Report;

use super::auth::{self, Session};
use super::dto::{ApiError, History, HostDetail, HostSummary, Snapshot};
use super::{ApiState, downsample};
use crate::store::now_unix_ms;

const HOUR_MS: u64 = 3_600_000;
const MAX_REPORTS: usize = 5_000;
const TARGET_POINTS: u64 = 500;

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/api/v1/healthz", get(|| async { "ok" }))
        .route("/api/v1/login", post(auth::login))
        .route("/api/v1/logout", post(auth::logout))
        .route("/api/v1/hosts", get(hosts))
        .route("/api/v1/hosts/{machine_id}", get(host))
        .route("/api/v1/hosts/{machine_id}/history", get(history))
        .route("/api/v1/hosts/{machine_id}/reports", get(reports))
        .route("/api/v1/hosts/{machine_id}/events", get(events))
        .route("/api/v1/live", get(live))
        .with_state(state)
}

async fn hosts(
    _s: Session,
    State(st): State<ApiState>,
) -> Result<Json<Vec<HostSummary>>, ApiError> {
    let now = now_unix_ms();
    let online_ms = st.online_secs.saturating_mul(1000);
    let out = st
        .store
        .list_hosts()
        .await?
        .into_iter()
        .map(|row| {
            let latest = st
                .live
                .latest_one(&row.machine_id)
                .map(|r| Snapshot::of(&r));
            HostSummary::build(row, latest, now, online_ms)
        })
        .collect();
    Ok(Json(out))
}

async fn host(
    _s: Session,
    State(st): State<ApiState>,
    Path(machine_id): Path<String>,
) -> Result<Json<HostDetail>, ApiError> {
    let row = st
        .store
        .list_hosts()
        .await?
        .into_iter()
        .find(|r| r.machine_id == machine_id)
        .ok_or_else(|| ApiError::not_found("unknown host"))?;

    let report = match st.live.latest_one(&machine_id) {
        Some(r) => (*r).clone(),
        None => st
            .store
            .latest_for(machine_id.clone())
            .await?
            .ok_or_else(|| ApiError::not_found("no reports for host"))?,
    };

    let now = now_unix_ms();
    let online_ms = st.online_secs.saturating_mul(1000);
    let summary = HostSummary::build(row, Some(Snapshot::of(&report)), now, online_ms);
    Ok(Json(HostDetail { summary, report }))
}

#[derive(Deserialize)]
struct RangeQuery {
    from: Option<u64>,
    to: Option<u64>,
    bucket: Option<u64>,
    limit: Option<usize>,
}

impl RangeQuery {
    /// `(from_ms, to_ms)` with defaults (last hour) and validation.
    fn window(&self) -> Result<(u64, u64), ApiError> {
        let to = self.to.unwrap_or_else(now_unix_ms);
        let from = self.from.unwrap_or_else(|| to.saturating_sub(HOUR_MS));
        if from >= to {
            return Err(ApiError::bad_request("`from` must be before `to`"));
        }
        Ok((from, to))
    }
}

async fn history(
    _s: Session,
    State(st): State<ApiState>,
    Path(machine_id): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<History>, ApiError> {
    if !st.store.host_exists(machine_id.clone()).await? {
        return Err(ApiError::not_found("unknown host"));
    }
    let (from_ms, to_ms) = q.window()?;
    let bucket_ms = q
        .bucket
        .filter(|b| *b > 0)
        .unwrap_or_else(|| downsample::pick_bucket(from_ms, to_ms, TARGET_POINTS));
    let buckets = st
        .store
        .history(machine_id.clone(), from_ms, to_ms, bucket_ms)
        .await?;
    Ok(Json(History {
        machine_id,
        from_ms,
        to_ms,
        bucket_ms,
        buckets,
    }))
}

async fn reports(
    _s: Session,
    State(st): State<ApiState>,
    Path(machine_id): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<Vec<Report>>, ApiError> {
    if !st.store.host_exists(machine_id.clone()).await? {
        return Err(ApiError::not_found("unknown host"));
    }
    let (from_ms, to_ms) = q.window()?;
    let limit = q.limit.unwrap_or(1000).clamp(1, MAX_REPORTS);
    let reports = st
        .store
        .recent_reports(machine_id, from_ms, to_ms, limit)
        .await?;
    Ok(Json(reports))
}

async fn events(
    _s: Session,
    State(st): State<ApiState>,
    Path(machine_id): Path<String>,
    Query(q): Query<RangeQuery>,
) -> Result<Json<Vec<crate::store::EventRow>>, ApiError> {
    if !st.store.host_exists(machine_id.clone()).await? {
        return Err(ApiError::not_found("unknown host"));
    }
    let (from_ms, to_ms) = q.window()?;
    let limit = q.limit.unwrap_or(1000).clamp(1, MAX_REPORTS);
    Ok(Json(
        st.store.events(machine_id, from_ms, to_ms, limit).await?,
    ))
}

async fn live(_s: Session, State(st): State<ApiState>) -> impl IntoResponse {
    let mut rx = st.live.subscribe();
    let snapshot = st.live.latest();

    let stream = async_stream::stream! {
        for report in snapshot {
            yield Ok::<Event, std::convert::Infallible>(sse_event(&report));
        }
        loop {
            match rx.recv().await {
                Ok(report) => yield Ok(sse_event(&report)),
                Err(RecvError::Lagged(_)) => {
                    for report in st.live.latest() {
                        yield Ok(sse_event(&report));
                    }
                }
                Err(RecvError::Closed) => break,
            }
        }
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(20))
            .text("ping"),
    )
}

fn sse_event(report: &Report) -> Event {
    Event::default()
        .json_data(report)
        .unwrap_or_else(|_| Event::default().comment("failed to encode report"))
}
