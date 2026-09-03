//! pulse-serverd internals. The `pulse-serverd` binary is a thin `main` over
//! [`run`]; the `pulse-server` binary is the (future) config/control front-end.

mod config;
mod connection;
mod registry;

pub use config::Config;

use std::io;
use std::sync::{Arc, Mutex};

use tokio::net::TcpListener;
use tracing::{error, info};

use registry::Registry;

/// Run the server: load config, set up logging, accept connections forever.
pub async fn run() -> io::Result<()> {
    let loaded = pulse_config::load::<Config>("server").unwrap_or_else(|err| {
        eprintln!("{err}");
        std::process::exit(1);
    });
    let cfg = loaded.config;

    let _log_guard = pulse_config::log::init("server", &cfg.log).unwrap_or_else(|err| {
        eprintln!("logging setup failed: {err}");
        std::process::exit(1);
    });

    if loaded.found {
        info!(path = %loaded.path.display(), "loaded config");
    } else {
        info!(path = %loaded.path.display(), "no config file, using defaults");
    }

    let listener = TcpListener::bind(&cfg.bind).await?;
    info!(bind = %cfg.bind, "pulse server listening");

    let registry = Arc::new(Mutex::new(Registry::default()));

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let registry = Arc::clone(&registry);
                tokio::spawn(async move {
                    if let Err(err) = connection::handle(stream, peer, registry).await {
                        error!(%peer, %err, "connection error");
                    }
                });
            }
            Err(err) => error!(%err, "accept failed"),
        }
    }
}
