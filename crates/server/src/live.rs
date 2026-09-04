//! In-memory "what's happening right now" view, separate from the historical
//! [`store`](crate::store) and from the identity-tracking
//! [`Registry`](crate::registry).
//!
//! Holds the newest [`Report`] per machine and a broadcast channel the API's
//! SSE stream subscribes to. Publishing never blocks the ingest path.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use protocol::Report;
use tokio::sync::broadcast;

pub struct Live {
    latest: Mutex<HashMap<String, Arc<Report>>>,
    tx: broadcast::Sender<Arc<Report>>,
}

impl Live {
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self {
            latest: Mutex::new(HashMap::new()),
            tx,
        }
    }

    /// Record a freshly received report and fan it out to SSE subscribers.
    /// `broadcast::send` never blocks; an error only means nobody is listening.
    pub fn publish(&self, report: Arc<Report>) {
        self.latest
            .lock()
            .unwrap()
            .insert(report.host.machine_id.clone(), Arc::clone(&report));
        let _ = self.tx.send(report);
    }

    /// Prime the map from storage at startup so the API has data before the
    /// first fresh report arrives.
    pub fn seed(&self, reports: impl IntoIterator<Item = Report>) {
        let mut map = self.latest.lock().unwrap();
        for r in reports {
            map.insert(r.host.machine_id.clone(), Arc::new(r));
        }
    }

    pub fn latest(&self) -> Vec<Arc<Report>> {
        self.latest.lock().unwrap().values().cloned().collect()
    }

    pub fn latest_one(&self, machine_id: &str) -> Option<Arc<Report>> {
        self.latest.lock().unwrap().get(machine_id).cloned()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Report>> {
        self.tx.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::{HostInfo, Metrics, Report};

    fn report(machine_id: &str, ts: u64) -> Report {
        let mut r = Report::new(
            HostInfo {
                machine_id: machine_id.into(),
                hostname: "h".into(),
                ..Default::default()
            },
            Metrics::default(),
        );
        r.timestamp_unix_ms = ts;
        r
    }

    #[test]
    fn publish_updates_latest() {
        let live = Live::new(16);
        live.publish(Arc::new(report("m1", 1)));
        live.publish(Arc::new(report("m1", 2)));
        live.publish(Arc::new(report("m2", 5)));
        assert_eq!(live.latest_one("m1").unwrap().timestamp_unix_ms, 2);
        assert_eq!(live.latest().len(), 2);
    }

    #[tokio::test]
    async fn subscriber_receives_published_reports() {
        let live = Live::new(16);
        let mut rx = live.subscribe();
        live.publish(Arc::new(report("m1", 7)));
        let got = rx.recv().await.unwrap();
        assert_eq!(got.host.machine_id, "m1");
        assert_eq!(got.timestamp_unix_ms, 7);
    }

    #[tokio::test]
    async fn lagged_subscriber_can_resume() {
        let live = Live::new(2);
        let mut rx = live.subscribe();
        for ts in 0..5 {
            live.publish(Arc::new(report("m1", ts)));
        }
        // The channel dropped older messages.
        assert!(matches!(
            rx.recv().await,
            Err(broadcast::error::RecvError::Lagged(_))
        ));
        // After a lag the receiver keeps working: eventually it sees a freshly
        // published report (tolerating further Lagged notices while it catches
        // up on the tiny buffer).
        live.publish(Arc::new(report("m1", 99)));
        let mut seen_99 = false;
        for _ in 0..16 {
            match rx.recv().await {
                Ok(r) if r.timestamp_unix_ms == 99 => {
                    seen_99 = true;
                    break;
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
        assert!(seen_99);
    }
}
