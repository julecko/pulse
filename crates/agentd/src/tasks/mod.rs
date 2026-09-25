//! The agent's independent background loops, each spawned separately in
//! `main`. See each submodule for what it does and how often.

mod auth_events;
mod health;
mod pairing;

pub use auth_events::auth_events_loop;
pub use health::check_health_periodically;
pub use pairing::pairing_loop;
