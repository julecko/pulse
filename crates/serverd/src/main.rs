mod alerting;
mod config;
mod credentials;
mod db;
mod geo_alerts;
mod geoip;
mod push;
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
        eprintln!("pulse-serverd: failed to load config: {err}");
        std::process::exit(1);
    });

    let _log_guard = match pulse_shared::init("server", &cfg.log) {
        Ok(guard) => guard,
        Err(err) => {
            eprintln!("pulse-serverd: failed to initialise logging: {err}");
            std::process::exit(1);
        }
    };

    tracing::info!("server starting");

    let pool = db::connect(&cfg.db).await.unwrap_or_else(|err| {
        tracing::error!("pulse-serverd: failed to connect to database: {err}");
        std::process::exit(1);
    });

    // Computed up front so the first login for an unknown user isn't
    // measurably slower than the rest (see `credentials::DUMMY_PASSWORD_HASH`).
    std::sync::LazyLock::force(&credentials::DUMMY_PASSWORD_HASH);

    let retention = db::retention::Retention::new(cfg.retention.clone());
    tokio::spawn(db::retention::cleanup_periodically(
        pool.clone(),
        retention.clone(),
    ));

    let push = push::Push::from_config(&cfg.push).unwrap_or_else(|err| {
        tracing::error!("pulse-serverd: push notifications: {err}");
        std::process::exit(1);
    });
    let geoip = geoip::GeoIp::load(&cfg.geoip);
    let alerting = alerting::Alerting::new(push, geo_alerts::GeoAlerts::new(geoip));

    if let Err(err) = web::serve(&cfg.web, pool, alerting, retention).await {
        tracing::error!("pulse-serverd: web server error: {err}");
        std::process::exit(1);
    }
}
