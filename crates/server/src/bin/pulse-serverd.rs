//! pulse-serverd — the pulse metrics server daemon.
//!
//! Not meant to be run by hand; it is started via systemd
//! (`systemctl start pulse-server`) or the `pulse-server` front-end.

// Multi-threaded: the ingest listener, the HTTP API, the pruner and the
// blocking SQLite pool all share this runtime.
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> std::io::Result<()> {
    pulse_server::run().await
}
