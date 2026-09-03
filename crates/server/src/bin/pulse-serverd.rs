//! pulse-serverd — the pulse metrics server daemon.
//!
//! Not meant to be run by hand; it is started via systemd
//! (`systemctl start pulse-server`) or the `pulse-server` front-end.

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    pulse_server::run().await
}
