//! Geo alert settings: which countries SSH logins may come from, whether
//! failed logins count, and whether geo alerts are pushed (see
//! [`crate::geo_alerts`]).

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use protocol::{
    GeoAlertSettings, GeoDatabaseInfo, MAX_ALLOWED_COUNTRIES, SetGeoAlertSettings,
    is_valid_country_code,
};
use sqlx::SqlitePool;

use super::auth::AuthedUser;
use crate::alerting::Alerting;

pub async fn get(
    State(pool): State<SqlitePool>,
    Extension(alerting): Extension<Arc<Alerting>>,
) -> Result<Json<GeoAlertSettings>, (StatusCode, String)> {
    load(&pool, &alerting).await.map(Json)
}

/// Replaces the settings. Country codes are uppercased and deduplicated;
/// an empty list turns geo alerts off.
pub async fn set(
    State(pool): State<SqlitePool>,
    Extension(alerting): Extension<Arc<Alerting>>,
    Extension(user): Extension<AuthedUser>,
    Json(req): Json<SetGeoAlertSettings>,
) -> Result<Json<GeoAlertSettings>, (StatusCode, String)> {
    let mut countries: Vec<String> = Vec::new();
    for code in &req.allowed_countries {
        let code = code.trim().to_ascii_uppercase();
        if !is_valid_country_code(&code) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "{:?} isn't a country code; use two-letter ISO codes like SK or DE",
                    protocol::escape_for_display(&code)
                ),
            ));
        }
        if !countries.contains(&code) {
            countries.push(code);
        }
    }
    if countries.len() > MAX_ALLOWED_COUNTRIES {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("at most {MAX_ALLOWED_COUNTRIES} countries"),
        ));
    }

    sqlx::query(
        "UPDATE geo_alert_settings
         SET allowed_countries = ?, include_failures = ?, notify = ?,
             updated_by = ?, updated_at = datetime('now')
         WHERE id = 1",
    )
    .bind(countries.join(","))
    .bind(req.include_failures)
    .bind(req.notify)
    .bind(&user.username)
    .execute(&pool)
    .await
    .map_err(super::internal_error)?;

    let settings = load(&pool, &alerting).await?;
    tracing::info!(
        allowed = %settings.allowed_countries.join(","),
        include_failures = settings.include_failures,
        notify = settings.notify,
        by = %user.username,
        "geo alert settings changed"
    );
    Ok(Json(settings))
}

async fn load(
    pool: &SqlitePool,
    alerting: &Alerting,
) -> Result<GeoAlertSettings, (StatusCode, String)> {
    let (allowed, include_failures, notify, updated_by, updated_at): (
        String,
        bool,
        bool,
        Option<String>,
        String,
    ) = sqlx::query_as(
        "SELECT allowed_countries, include_failures, notify, updated_by, updated_at
         FROM geo_alert_settings WHERE id = 1",
    )
    .fetch_one(pool)
    .await
    .map_err(super::internal_error)?;

    let database = match alerting.geo().database() {
        Some((path, database_type, built)) => {
            let built_at: String = sqlx::query_scalar("SELECT datetime(?, 'unixepoch')")
                .bind(i64::try_from(built).unwrap_or(0))
                .fetch_one(pool)
                .await
                .map_err(super::internal_error)?;
            Some(GeoDatabaseInfo {
                path: path.display().to_string(),
                database_type: database_type.to_string(),
                built_at,
            })
        }
        None => None,
    };

    Ok(GeoAlertSettings {
        allowed_countries: allowed
            .split(',')
            .filter(|c| !c.is_empty())
            .map(str::to_string)
            .collect(),
        include_failures,
        notify,
        updated_by,
        updated_at,
        database,
    })
}
