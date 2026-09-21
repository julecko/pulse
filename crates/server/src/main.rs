mod config;
mod web;

use config::ServerConfig;

#[tokio::main]
async fn main() {
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

    if let Err(err) = web::serve(&cfg.web).await {
        tracing::error!("server: web server error: {err}");
        std::process::exit(1);
    }
}
