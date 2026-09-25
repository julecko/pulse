//! The agent's independent background loops, each spawned separately in
//! `main`. See each submodule for what it does and how often.

mod auth_events;
mod metrics;
mod pairing;

pub use auth_events::auth_events_loop;
pub use metrics::send_metrics_periodically;
pub use pairing::pairing_loop;
