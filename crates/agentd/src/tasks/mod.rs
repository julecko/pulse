//! The agent's independent background loops, each spawned separately in
//! `main`. See each submodule for what it does and how often.

mod local_socket;
mod metrics;
mod pairing;

pub use local_socket::local_socket_loop;
pub use metrics::send_metrics_periodically;
pub use pairing::pairing_loop;
