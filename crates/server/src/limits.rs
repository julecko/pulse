//! Cheap per-source-IP connection rate limiting (fixed 60s window).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);
const PRUNE_AT: usize = 8192;

pub struct RateLimiter {
    per_minute: u32,
    seen: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl RateLimiter {
    pub fn new(per_minute: u32) -> Self {
        Self {
            per_minute,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Record a connection attempt from `ip`; `false` means it is over the limit
    /// and should be dropped.
    pub fn allow(&self, ip: IpAddr) -> bool {
        if self.per_minute == 0 {
            return true;
        }
        let now = Instant::now();
        let mut seen = self.seen.lock().unwrap();

        if seen.len() > PRUNE_AT {
            seen.retain(|_, (start, _)| now.duration_since(*start) < WINDOW);
        }

        let (start, count) = seen.entry(ip).or_insert((now, 0));
        if now.duration_since(*start) >= WINDOW {
            *start = now;
            *count = 0;
        }
        *count += 1;
        *count <= self.per_minute
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_the_limit_then_blocks() {
        let rl = RateLimiter::new(3);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(rl.allow(ip));
        assert!(rl.allow(ip));
        assert!(rl.allow(ip));
        assert!(!rl.allow(ip));
        assert!(!rl.allow(ip));
        // a different source is independent
        assert!(rl.allow("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn zero_means_unlimited() {
        let rl = RateLimiter::new(0);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..1000 {
            assert!(rl.allow(ip));
        }
    }
}
