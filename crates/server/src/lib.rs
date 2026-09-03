//! pulse-serverd internals. The `pulse-serverd` binary is a thin `main` over
//! [`run`]; the `pulse-server` binary is the config/control front-end.

mod config;
mod connection;
mod registry;

pub use config::Config;

use std::io;
use std::sync::{Arc, Mutex};

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

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

    let acceptor: Option<TlsAcceptor> = match &cfg.tls {
        Some(tls) => {
            let server_config = pulse_config::tls::server_config(&tls.cert, &tls.key)
                .unwrap_or_else(|err| {
                    eprintln!("tls: {err}");
                    std::process::exit(1);
                });
            Some(TlsAcceptor::from(server_config))
        }
        None => None,
    };

    let listener = TcpListener::bind(&cfg.bind).await?;
    info!(bind = %cfg.bind, tls = acceptor.is_some(), "pulse server listening");
    if acceptor.is_none() {
        warn!("TLS is not configured — traffic is unencrypted (see `pulse-server cert generate`)");
    }

    let registry = Arc::new(Mutex::new(Registry::default()));

    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                let registry = Arc::clone(&registry);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match acceptor {
                        Some(acceptor) => match acceptor.accept(tcp).await {
                            Ok(tls) => serve(tls, peer, registry).await,
                            Err(err) => warn!(%peer, %err, "TLS handshake failed"),
                        },
                        None => serve(tcp, peer, registry).await,
                    }
                });
            }
            Err(err) => error!(%err, "accept failed"),
        }
    }
}

async fn serve<S>(stream: S, peer: std::net::SocketAddr, registry: Arc<Mutex<Registry>>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if let Err(err) = connection::handle(stream, peer, registry).await {
        error!(%peer, %err, "connection error");
    }
}
