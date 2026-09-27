//! Rate limiting for the routes an unauthenticated client can reach
//! (`/auth/login`, `/agents/pair`): per client IP via [`enforce`], and for
//! logins also per username (see `users::login`), since per-IP limits alone
//! don't stop a guesser with many addresses. The agents' own routes are
//! limited per agent ([`enforce_per_agent`]), so one agent (or a stolen
//! agent secret) can't flood the database.
//!
//! A token bucket per client: it holds up to `per_minute` requests and
//! refills at `per_minute` per minute, so a client can burst up to the full
//! minute's allowance and then continues at the steady rate. Over the limit
//! gets `429 Too Many Requests` with `Retry-After`.
//!
//! The login limiter only counts failures: a successful login gives its
//! token back, so an admin running many `pulse-server-cli` commands (each
//! logs in) isn't locked out, while password guessing stays capped.
//!
//! IPv6 clients are grouped per /64, since one host usually controls a
//! whole /64 and could otherwise rotate addresses to dodge the limit.
//!
//! Behind a reverse proxy every request comes from the proxy's IP, so all
//! clients would share one bucket; rate-limit at the proxy instead and set
//! the limits here to 0.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Extension;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

/// Clients tracked per limiter before idle ones are pruned; bounds memory
/// when many different IPs show up.
const MAX_TRACKED_CLIENTS: usize = 10_000;
/// How many clients are left after an eviction (see
/// [`RateLimiter::evict_least_throttled`]); below the cap, so a flood
/// doesn't trigger one on every request.
const EVICT_DOWN_TO: usize = MAX_TRACKED_CLIENTS * 3 / 4;

/// The server config's `[web.rate_limit]` section. `0` disables a limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Failed `POST /auth/login` attempts per client IP per minute
    /// (successful logins don't count).
    pub login_failures_per_minute: u32,
    /// Failed `POST /auth/login` attempts per username per minute, from
    /// any IP. Throttles (never locks) the account, so guessing from many
    /// addresses stays slow while the real user can still get in.
    pub login_failures_per_user_per_minute: u32,
    /// `POST /agents/pair` requests per client IP per minute. Every agent
    /// polls once a minute, even after approval, so this also caps how many
    /// agents can share one public IP (e.g. behind NAT).
    pub pair_per_minute: u32,
    /// `POST /agents/me/metrics` per agent per minute. Agents send one
    /// snapshot per `interval_secs` (default 60), so 4 allows intervals
    /// down to 15s.
    pub metrics_per_agent_per_minute: u32,
    /// `POST /agents/me/auth-events` per agent per minute: one per PAM
    /// event, so generous enough for a host under SSH brute force.
    pub auth_events_per_agent_per_minute: u32,
    /// `POST /agents/me/notify` per agent per minute: plain push
    /// notifications from `pulse-agent-cli notify`, so a script (or a
    /// stolen agent secret) can't flood everyone's phone.
    pub notifications_per_agent_per_minute: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            login_failures_per_minute: 5,
            login_failures_per_user_per_minute: 5,
            pair_per_minute: 30,
            metrics_per_agent_per_minute: 4,
            auth_events_per_agent_per_minute: 300,
            notifications_per_agent_per_minute: 10,
        }
    }
}

/// A token bucket per key: client IP (see [`client_key`]) or username.
pub struct RateLimiter<K = IpAddr> {
    /// Route name, for logs.
    name: &'static str,
    capacity: f64,
    refill_per_sec: f64,
    /// Give the token back when the response is a success, so only failed
    /// requests count.
    count_failures_only: bool,
    buckets: Mutex<HashMap<K, Bucket>>,
}

struct Bucket {
    tokens: f64,
    updated: Instant,
}

impl<K: Hash + Eq + Clone> RateLimiter<K> {
    /// Counts every request. `None` when `per_minute` is 0 (disabled).
    pub fn new(name: &'static str, per_minute: u32) -> Option<Arc<Self>> {
        Self::build(name, per_minute, false)
    }

    /// Counts only requests that don't get a success response. `None` when
    /// `per_minute` is 0 (disabled).
    pub fn failures_only(name: &'static str, per_minute: u32) -> Option<Arc<Self>> {
        Self::build(name, per_minute, true)
    }

    fn build(name: &'static str, per_minute: u32, count_failures_only: bool) -> Option<Arc<Self>> {
        (per_minute > 0).then(|| {
            Arc::new(Self {
                name,
                capacity: f64::from(per_minute),
                refill_per_sec: f64::from(per_minute) / 60.0,
                count_failures_only,
                buckets: Mutex::new(HashMap::new()),
            })
        })
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Gives back the token [`Self::check`] took from `key`.
    pub fn refund(&self, key: &K) {
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(bucket) = buckets.get_mut(key) {
            bucket.tokens = (bucket.tokens + 1.0).min(self.capacity);
        }
    }

    /// Takes one request from `key`'s bucket, or returns how long until it
    /// has one again.
    pub fn check(&self, key: K, now: Instant) -> Result<(), Duration> {
        // Nothing in here can panic mid-update, so a poisoned lock is fine.
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());

        if buckets.len() >= MAX_TRACKED_CLIENTS {
            // A full bucket behaves exactly like a missing one, so dropping
            // those loses nothing.
            buckets.retain(|_, b| self.refilled(b, now) < self.capacity);
            if buckets.len() >= MAX_TRACKED_CLIENTS {
                self.evict_least_throttled(&mut buckets, now);
            }
        }

        let bucket = buckets.entry(key).or_insert(Bucket {
            tokens: self.capacity,
            updated: now,
        });
        bucket.tokens = self.refilled(bucket, now);
        bucket.updated = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64(
                (1.0 - bucket.tokens) / self.refill_per_sec,
            ))
        }
    }

    /// Drops the buckets with the most tokens left until
    /// [`EVICT_DOWN_TO`] remain. Clearing everything instead would let
    /// someone with many addresses (or junk usernames) reset a throttled
    /// client just by flooding the map; this way the most throttled
    /// clients are the last to be forgotten, and flooding buckets (at most
    /// one request short of full) always go first.
    fn evict_least_throttled(&self, buckets: &mut HashMap<K, Bucket>, now: Instant) {
        let mut by_tokens: Vec<(f64, K)> = buckets
            .iter()
            .map(|(key, b)| (self.refilled(b, now), key.clone()))
            .collect();
        by_tokens.sort_unstable_by(|a, b| b.0.total_cmp(&a.0));
        let excess = buckets.len().saturating_sub(EVICT_DOWN_TO);
        for (_, key) in by_tokens.into_iter().take(excess) {
            buckets.remove(&key);
        }
        tracing::warn!(
            limiter = self.name,
            evicted = excess,
            "rate limiter tracking too many clients; forgot the least throttled"
        );
    }

    fn refilled(&self, bucket: &Bucket, now: Instant) -> f64 {
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity)
    }
}

/// IPv4 addresses as-is, IPv6 grouped per /64 (IPv4-mapped IPv6 counts as
/// the IPv4 address).
pub(super) fn client_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let prefix = u128::from(v6) & !((1u128 << 64) - 1);
            IpAddr::V6(prefix.into())
        }
        v4 => v4,
    }
}

/// Middleware: `429` with `Retry-After` once the client's bucket is empty.
pub async fn enforce(
    State(limiter): State<Arc<RateLimiter>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let key = client_key(peer.ip());
    match limiter.check(key, Instant::now()) {
        Ok(()) => {
            let resp = next.run(req).await;
            if limiter.count_failures_only && resp.status().is_success() {
                limiter.refund(&key);
            }
            resp
        }
        Err(retry_after) => {
            tracing::warn!(limiter = limiter.name, peer = %peer.ip(), "rate limited");
            too_many_requests(retry_after)
        }
    }
}

/// Middleware for routes behind [`super::auth::require_agent`] (which must
/// run first): `429` with `Retry-After` once the calling agent's bucket is
/// empty. Counts every request.
pub async fn enforce_per_agent(
    State(limiter): State<Arc<RateLimiter<i64>>>,
    Extension(agent): Extension<super::auth::AuthedAgent>,
    req: Request,
    next: Next,
) -> Response {
    match limiter.check(agent.id, Instant::now()) {
        Ok(()) => next.run(req).await,
        Err(retry_after) => {
            tracing::warn!(limiter = limiter.name, agent_id = agent.id, "rate limited");
            too_many_requests(retry_after)
        }
    }
}

/// `429` with `Retry-After`.
pub fn too_many_requests(retry_after: Duration) -> Response {
    let secs = retry_after.as_secs().max(1);
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, secs.to_string())],
        format!("too many requests; retry in {secs}s"),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_burst_then_limits_then_refills() {
        let limiter = RateLimiter::new("test", 3).unwrap();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let t0 = Instant::now();

        for _ in 0..3 {
            assert!(limiter.check(ip, t0).is_ok());
        }
        let wait = limiter.check(ip, t0).unwrap_err();
        assert_eq!(wait.as_secs(), 20); // 3/min = one every 20s

        // Other clients have their own bucket.
        assert!(limiter.check("192.0.2.2".parse().unwrap(), t0).is_ok());

        assert!(limiter.check(ip, t0 + Duration::from_secs(20)).is_ok());
        assert!(limiter.check(ip, t0 + Duration::from_secs(20)).is_err());
    }

    #[test]
    fn refund_restores_a_token() {
        let limiter = RateLimiter::failures_only("test", 1).unwrap();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let t0 = Instant::now();
        assert!(limiter.check(ip, t0).is_ok());
        limiter.refund(&ip);
        assert!(limiter.check(ip, t0).is_ok());
        assert!(limiter.check(ip, t0).is_err());
    }

    #[test]
    fn flooding_the_map_does_not_reset_a_throttled_client() {
        let limiter = RateLimiter::<String>::failures_only("test", 5).unwrap();
        let t0 = Instant::now();
        for _ in 0..5 {
            assert!(limiter.check("victim".to_string(), t0).is_ok());
        }
        assert!(limiter.check("victim".to_string(), t0).is_err());

        // One failure each for more junk names than the limiter tracks.
        for i in 0..MAX_TRACKED_CLIENTS * 2 {
            let _ = limiter.check(format!("junk{i}"), t0);
        }

        assert!(
            limiter.check("victim".to_string(), t0).is_err(),
            "victim's bucket must survive eviction"
        );
        assert!(limiter.buckets.lock().unwrap().len() <= MAX_TRACKED_CLIENTS);
    }

    #[test]
    fn keys_by_username() {
        let limiter = RateLimiter::<String>::failures_only("test", 2).unwrap();
        let t0 = Instant::now();
        for _ in 0..2 {
            assert!(limiter.check("alice".to_string(), t0).is_ok());
        }
        assert!(limiter.check("alice".to_string(), t0).is_err());
        assert!(limiter.check("bob".to_string(), t0).is_ok());
    }

    #[test]
    fn groups_ipv6_by_64_and_unmaps_ipv4() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:bbbb::2".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(client_key(a), client_key(b));
        assert_ne!(client_key(a), client_key(c));
        assert_eq!(
            client_key("::ffff:192.0.2.1".parse().unwrap()),
            client_key("192.0.2.1".parse().unwrap())
        );
    }
}
