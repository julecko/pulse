//! pulse-serverd internals. The `pulse-serverd` binary is a thin `main` over
//! [`run`]; the `pulse-server` binary is the config/control front-end.

mod config;
mod connection;
mod limits;
mod registry;

pub use config::Config;

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use limits::RateLimiter;
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

    let acceptor: Option<TlsAcceptor> = if cfg.tls {
        let dir = pulse_config::dir("server");
        let server_config = pulse_config::tls::server_config(
            &dir.join("server.crt"),
            &dir.join("server.key"),
            &dir.join("trusted-agents"),
        )
        .unwrap_or_else(|err| {
            eprintln!("tls: {err}");
            std::process::exit(1);
        });
        Some(TlsAcceptor::from(server_config))
    } else {
        None
    };

    let listener = TcpListener::bind(&cfg.bind).await?;
    info!(
        bind = %cfg.bind,
        tls = acceptor.is_some(),
        max_connections = cfg.limits.max_connections,
        per_ip_per_minute = cfg.limits.per_ip_per_minute,
        "pulse server listening"
    );
    if acceptor.is_none() {
        warn!("TLS is not configured — traffic is unencrypted and unauthenticated");
    }

    let registry = Arc::new(Mutex::new(Registry::default()));
    let rate = Arc::new(RateLimiter::new(cfg.limits.per_ip_per_minute));
    let slots = Arc::new(Semaphore::new(if cfg.limits.max_connections == 0 {
        Semaphore::MAX_PERMITS
    } else {
        cfg.limits.max_connections
    }));
    let timeout = match cfg.limits.connection_timeout_secs {
        0 => None,
        s => Some(Duration::from_secs(s)),
    };

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                error!(%err, "accept failed");
                continue;
            }
        };

        if !rate.allow(peer.ip()) {
            warn!(%peer, "rate limited — dropping connection");
            continue;
        }
        let permit = match Arc::clone(&slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!(%peer, "connection limit reached — dropping connection");
                continue;
            }
        };

        let registry = Arc::clone(&registry);
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let work = drive(acceptor, tcp, peer, registry);
            match timeout {
                Some(dur) => {
                    if tokio::time::timeout(dur, work).await.is_err() {
                        warn!(%peer, "connection timed out");
                    }
                }
                None => work.await,
            }
        });
    }
}

async fn drive(
    acceptor: Option<TlsAcceptor>,
    tcp: TcpStream,
    peer: SocketAddr,
    registry: Arc<Mutex<Registry>>,
) {
    match acceptor {
        Some(acceptor) => match acceptor.accept(tcp).await {
            Ok(tls) => serve(tls, peer, registry).await,
            Err(err) => warn!(%peer, %err, "TLS handshake failed"),
        },
        None => serve(tcp, peer, registry).await,
    }
}

async fn serve<S>(stream: S, peer: SocketAddr, registry: Arc<Mutex<Registry>>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if let Err(err) = connection::handle(stream, peer, registry).await {
        error!(%peer, %err, "connection error");
    }
}
