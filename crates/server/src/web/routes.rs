//! Route definitions. Add new routes here and wire them into [`router`].

use axum::Router;
use axum::routing::get;

pub fn router() -> Router {
    Router::new().route("/healthz", get(healthz))
}

async fn healthz() -> &'static str {
    "ok"
}
