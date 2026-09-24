//! The agent's independent background loops, each spawned separately in
//! `main`. See each submodule for what it does and how often.

mod health;
mod metrics;
mod pairing;

pub use health::check_health_periodically;
pub use metrics::print_metrics_periodically;
pub use pairing::pairing_loop;
