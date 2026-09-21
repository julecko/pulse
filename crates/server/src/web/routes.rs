//! Route definitions. Add new routes here and wire them into [`router`].

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use sqlx::SqlitePool;

pub fn router(pool: SqlitePool) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/hosts", get(list_hosts))
        .with_state(pool)
}

async fn healthz() -> &'static str {
    "ok"
}

/// Example query route: returns `hostname` for every row in the `hosts`
/// table seeded by `migrations/0001_create_hosts.sql`.
async fn list_hosts(State(pool): State<SqlitePool>) -> Result<String, (StatusCode, String)> {
    let hostnames: Vec<String> = sqlx::query_scalar("SELECT hostname FROM hosts ORDER BY id")
        .fetch_all(&pool)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(hostnames.join("\n"))
}
