mod connection;
mod registry;

use std::io;
use std::sync::{Arc, Mutex};

use tokio::net::TcpListener;

use registry::Registry;

const DEFAULT_BIND: &str = "127.0.0.1:9000";

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let bind = std::env::var("PULSE_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());
    let listener = TcpListener::bind(&bind).await?;
    println!("pulse server listening on {bind}");

    let registry = Arc::new(Mutex::new(Registry::default()));

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let registry = Arc::clone(&registry);
                tokio::spawn(async move {
                    if let Err(err) = connection::handle(stream, peer, registry).await {
                        eprintln!("connection error ({peer}): {err}");
                    }
                });
            }
            Err(err) => eprintln!("accept failed: {err}"),
        }
    }
}
