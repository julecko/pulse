//! Collects a metrics snapshot every `interval_secs` (agent config) and
//! sends it to `POST /agents/me/metrics`.
//!
//! Like PAM events, nothing is kept on the agent: if it isn't paired yet or
//! the send fails, that snapshot is dropped and the next tick sends a fresh
//! one.

use std::time::Duration;

use tokio::sync::watch;
use tokio::time::MissedTickBehavior;

use crate::collectors;

pub async fn send_metrics_periodically(
    client: reqwest::Client,
    url: String,
    interval: Duration,
    token: watch::Receiver<Option<String>>,
) {
    let mut ticker = tokio::time::interval(interval);
    // If a tick is late (slow collection or send), wait a full interval
    // before the next one instead of firing a burst to catch up.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;

        let Some(token) = token.borrow().clone() else {
            tracing::debug!("not paired; skipping metrics");
            continue;
        };

        // Collectors block (sysinfo calls, and the CPU sample sleeps), so
        // keep them off the async worker threads.
        let metrics = match tokio::task::spawn_blocking(collectors::collect).await {
            Ok(metrics) => metrics,
            Err(err) => {
                tracing::warn!(%err, "metrics collection panicked");
                continue;
            }
        };

        match client
            .post(&url)
            .bearer_auth(&token)
            .json(&metrics)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!("sent metrics");
            }
            Ok(resp) => {
                tracing::warn!(status = %resp.status(), "server rejected metrics; dropped");
            }
            Err(err) => {
                tracing::warn!(%err, "failed to send metrics; dropped");
            }
        }
    }
}
