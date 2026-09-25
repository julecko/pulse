mod config;
mod db;
mod web;

use config::ServerConfig;

#[tokio::main]
async fn main() {
    // The dependency graph pulls in both the `ring` and `aws-lc-rs` rustls
    // crypto backends (via axum-server and reqwest respectively, sharing
    // one workspace Cargo.lock); rustls refuses to guess between them, so
    // pin one explicitly before any TLS work happens.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install default rustls crypto provider");

    let cfg: ServerConfig = pulse_shared::config::load("server").unwrap_or_else(|err| {
        eprintln!("server: failed to load config: {err}");
        std::process::exit(1);
    });

    let _log_guard = match pulse_shared::init("server", &cfg.log) {
        Ok(guard) => guard,
        Err(err) => {
            eprintln!("server: failed to initialise logging: {err}");
            std::process::exit(1);
        }
    };

    tracing::info!("server starting");

    let pool = db::connect(&cfg.db).await.unwrap_or_else(|err| {
        tracing::error!("server: failed to connect to database: {err}");
        std::process::exit(1);
    });

    tokio::spawn(db::retention::cleanup_periodically(
        pool.clone(),
        cfg.retention.clone(),
    ));

    if let Err(err) = web::serve(&cfg.web, pool).await {
        tracing::error!("server: web server error: {err}");
        std::process::exit(1);
    }
}
