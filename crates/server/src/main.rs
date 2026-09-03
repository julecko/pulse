mod config;
mod connection;
mod registry;

use std::io;
use std::sync::{Arc, Mutex};

use tokio::net::TcpListener;

use registry::Registry;

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let loaded = pulse_config::load::<config::Config>("server").unwrap_or_else(|err| {
        eprintln!("{err}");
        std::process::exit(1);
    });
    if loaded.found {
        println!("config: loaded {}", loaded.path.display());
    } else {
        println!("config: none at {}, using defaults", loaded.path.display());
    }
    let cfg = loaded.config;

    let listener = TcpListener::bind(&cfg.bind).await?;
    println!("pulse server listening on {}", cfg.bind);

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
