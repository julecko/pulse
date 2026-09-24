use std::time::Duration;

use crate::collectors;

const METRICS_PRINT_INTERVAL: Duration = Duration::from_secs(20);

pub async fn print_metrics_periodically() {
    let mut ticker = tokio::time::interval(METRICS_PRINT_INTERVAL);
    loop {
        ticker.tick().await;
        let metrics = collectors::collect();
        tracing::info!(?metrics, "collected metrics");
    }
}
