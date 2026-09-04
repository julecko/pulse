//! pulse-serverd — the pulse metrics server daemon.
//!
//! Not meant to be run by hand; it is started via systemd
//! (`systemctl start pulse-server`) or the `pulse-server` front-end.

// The ingest listener, the HTTP API, the pruner and the blocking SQLite pool all
// share this runtime. Thread counts are capped: 2 async workers, and a bounded
// blocking pool so a burst of Argon2 logins (memory-hard) can't spawn hundreds
// of threads.
fn main() -> std::io::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(32)
        .enable_all()
        .build()?
        .block_on(pulse_server::run())
}
