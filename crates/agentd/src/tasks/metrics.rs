//! Collects a metrics snapshot every `interval_secs` (agent config) and
//! sends it to `POST /agents/me/metrics`. CPU usage in each snapshot is the
//! average over that whole interval.
//!
//! Like PAM events, nothing is kept on the agent: if it isn't paired yet or
//! the send fails, that snapshot is dropped and the next tick sends a fresh
//! one.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::{Instant, MissedTickBehavior};

use crate::collectors::{self, Context};

pub async fn send_metrics_periodically(
    client: reqwest::Client,
    url: String,
    interval: Duration,
    token: watch::Receiver<Option<String>>,
) {
    // Taken now, so this is the CPU baseline; the first snapshot comes one
    // full interval later rather than immediately, so it's a real average.
    // Behind a mutex only so it can move into spawn_blocking and back.
    let ctx = Arc::new(Mutex::new(Context::new()));
    let mut ticker = tokio::time::interval_at(Instant::now() + interval, interval);
    // If a tick is late (slow collection or send), wait a full interval
    // before the next one instead of firing a burst to catch up.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;

        // Collect even when unpaired, so the CPU average always covers just
        // the last interval, not everything since pairing. sysinfo calls
        // block, so keep them off the async worker threads.
        let ctx = Arc::clone(&ctx);
        let collected = tokio::task::spawn_blocking(move || {
            // A panic mid-collection leaves nothing half-updated worth
            // distrusting, so a poisoned lock is safe to reuse.
            let mut ctx = ctx.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            collectors::collect(&mut ctx)
        })
        .await;

        let Some(token) = token.borrow().clone() else {
            tracing::debug!("not paired; dropping metrics");
            continue;
        };

        let metrics = match collected {
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
