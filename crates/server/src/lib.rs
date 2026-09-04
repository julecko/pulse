//! pulse-serverd internals. The `pulse-serverd` binary is a thin `main` over
//! [`run`]; the `pulse-server` binary is the config/control front-end.

mod api;
mod config;
mod connection;
mod limits;
mod live;
mod password;
mod registry;
mod store;

pub mod admin;

pub use config::Config;

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use limits::RateLimiter;
use live::Live;
use registry::Registry;
use store::{StoreHandle, now_unix_ms};

/// Path of the history database for `cfg` — `[storage] path`, or
/// `<state dir>/history.db` when unset. Shared by the daemon and the
/// `pulse-server user` CLI.
pub fn history_db_path(cfg: &Config) -> PathBuf {
    if cfg.storage.path.is_empty() {
        pulse_config::state_dir("server").join("history.db")
    } else {
        PathBuf::from(&cfg.storage.path)
    }
}

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

    let store = if cfg.storage.enabled {
        let path = history_db_path(&cfg);
        match StoreHandle::open_sqlite(&path) {
            Ok(store) => {
                info!(
                    path = %path.display(),
                    retention_days = cfg.storage.retention_days,
                    "history storage enabled"
                );
                store
            }
            Err(err) => {
                eprintln!("storage: {err}");
                std::process::exit(1);
            }
        }
    } else {
        info!("history storage disabled (storage.enabled = false)");
        StoreHandle::noop()
    };

    if store.is_persistent() {
        spawn_pruner(store.clone(), &cfg.storage);
    }

    let live = Arc::new(Live::new(cfg.api.live_buffer.max(16)));
    if store.is_persistent() {
        match store.latest_per_host().await {
            Ok(reports) => live.seed(reports),
            Err(err) => warn!(%err, "could not seed live state from storage"),
        }
    }

    if cfg.api.enabled {
        if !store.is_persistent() {
            eprintln!("api: [api] enabled requires [storage] enabled = true");
            std::process::exit(1);
        }
        match store.user_count().await {
            Ok(0) => warn!(
                "API is enabled but no accounts exist — create one with `pulse-server user add <name>`"
            ),
            Ok(n) => info!(accounts = n, "API accounts loaded"),
            Err(err) => warn!(%err, "could not count API accounts"),
        }
        // Bind + load TLS now so a misconfigured/occupied port or a
        // missing/bad cert fails the daemon instead of leaving it "healthy"
        // with no API.
        let api_listener = api::bind(&cfg.api).unwrap_or_else(|err| {
            eprintln!("api: cannot bind {}: {err}", cfg.api.bind);
            std::process::exit(1);
        });
        let api_tls = api::load_tls(&cfg.api).unwrap_or_else(|err| {
            eprintln!("api: tls: {err}");
            std::process::exit(1);
        });
        if api_tls.is_some() {
            info!("API serving HTTPS");
        } else {
            warn!(
                "API is plaintext HTTP — set [api] tls = true or terminate TLS at a reverse proxy"
            );
        }
        let api_cfg = cfg.api.clone();
        let api_store = store.clone();
        let api_live = Arc::clone(&live);
        tokio::spawn(async move {
            if let Err(err) = api::serve(api_listener, api_tls, api_cfg, api_store, api_live).await
            {
                error!(%err, "API server stopped");
            }
        });
    }

    let acceptor: Option<TlsAcceptor> = if cfg.tls {
        let dir = pulse_config::tls_dir("server");
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
        let store = store.clone();
        let live = Arc::clone(&live);
        tokio::spawn(async move {
            let _permit = permit;
            let work = drive(acceptor, tcp, peer, registry, store, live);
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
    store: StoreHandle,
    live: Arc<Live>,
) {
    match acceptor {
        Some(acceptor) => match acceptor.accept(tcp).await {
            Ok(tls) => serve(tls, peer, registry, store, live).await,
            Err(err) => warn!(%peer, %err, "TLS handshake failed"),
        },
        None => serve(tcp, peer, registry, store, live).await,
    }
}

async fn serve<S>(
    stream: S,
    peer: SocketAddr,
    registry: Arc<Mutex<Registry>>,
    store: StoreHandle,
    live: Arc<Live>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if let Err(err) = connection::handle(stream, peer, registry, store, live).await {
        error!(%peer, %err, "connection error");
    }
}

/// Background task: every `prune_interval_secs` (min 60s), delete report rows
/// older than the retention window. `tokio::time::interval` fires immediately,
/// so a stale DB is trimmed at startup.
fn spawn_pruner(store: StoreHandle, storage: &config::Storage) {
    // `max(1)` so `retention_days = 0` doesn't degenerate into "delete everything
    // older than now"; `saturating_mul` guards the (already generous) u64 range.
    let retention_ms = (storage.retention_days.max(1) as u64).saturating_mul(86_400_000);
    let period = Duration::from_secs(storage.prune_interval_secs.max(60));
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(period);
        loop {
            tick.tick().await;
            let cutoff = now_unix_ms().saturating_sub(retention_ms);
            match store.prune(cutoff).await {
                Ok(0) => {}
                Ok(n) => info!(deleted = n, "pruned reports past retention"),
                Err(err) => warn!(%err, "prune failed"),
            }
            match store.prune_sessions(now_unix_ms()).await {
                Ok(0) => {}
                Ok(n) => info!(deleted = n, "pruned expired sessions"),
                Err(err) => warn!(%err, "session prune failed"),
            }
        }
    });
}
