mod config;
mod credentials;
mod db;
mod user_cli;
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

    // `server user ...` manages accounts directly in the database and exits;
    // no args runs the server.
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None => {}
        Some("user") => {
            let pool = db::connect(&cfg.db).await.unwrap_or_else(|err| {
                eprintln!("server: failed to connect to database: {err}");
                std::process::exit(1);
            });
            if let Err(err) = user_cli::run(&args[1..], &pool).await {
                eprintln!("server: {err}");
                std::process::exit(1);
            }
            return;
        }
        Some(other) => {
            eprintln!("server: unknown command {other:?}\nusage: server [user ...]");
            std::process::exit(2);
        }
    }

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

    // Computed up front so the first login for an unknown user isn't
    // measurably slower than the rest (see `credentials::DUMMY_PASSWORD_HASH`).
    std::sync::LazyLock::force(&credentials::DUMMY_PASSWORD_HASH);

    tokio::spawn(db::retention::cleanup_periodically(
        pool.clone(),
        cfg.retention.clone(),
    ));

    if let Err(err) = web::serve(&cfg.web, pool).await {
        tracing::error!("server: web server error: {err}");
        std::process::exit(1);
    }
}
