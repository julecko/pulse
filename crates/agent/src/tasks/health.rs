use std::time::Duration;

const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(5);

pub async fn check_health_periodically(client: reqwest::Client, url: String) {
    let mut ticker = tokio::time::interval(HEALTH_CHECK_INTERVAL);
    loop {
        ticker.tick().await;
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(status = %resp.status(), "server healthy");
            }
            Ok(resp) => {
                tracing::warn!(status = %resp.status(), "server responded with error status");
            }
            Err(err) => {
                tracing::warn!(%err, "health check failed");
            }
        }
    }
}
