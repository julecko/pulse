//! Android app releases, which the app downloads to update itself (see
//! [`crate::app_releases`] for where the APKs are kept):
//!
//! - `GET /app-releases`: every release, newest first
//! - `GET /app-releases/latest`: the one with the highest version code
//!   (`404` if none was uploaded)
//! - `GET /app-releases/{version_code}/apk`: the APK itself (supports
//!   `Range`, so an interrupted download can resume)
//! - `PUT /app-releases/{version_code}?version_name=1.2&notes=...`: upload;
//!   the body is the APK. `409` if that version code already exists
//! - `DELETE /app-releases/{version_code}`

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use futures_util::StreamExt;
use protocol::{
    AppRelease, MAX_APP_RELEASE_NOTES_LEN, MAX_APP_VERSION_CODE, NewAppRelease,
    is_valid_app_version_name,
};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use tokio::io::AsyncWriteExt;
use tower::ServiceExt;
use tower_http::services::ServeFile;

use super::auth::AuthedUser;
use crate::alerting::Alerting;
use crate::app_releases::AppReleases;
use crate::push::PushMessage;

const APK_MIME: &str = "application/vnd.android.package-archive";

#[derive(sqlx::FromRow)]
struct ReleaseRow {
    version_code: i64,
    version_name: String,
    notes: Option<String>,
    size: i64,
    sha256: String,
    uploaded_by: Option<String>,
    created_at: String,
}

impl From<ReleaseRow> for AppRelease {
    fn from(row: ReleaseRow) -> Self {
        AppRelease {
            version_code: row.version_code as u32,
            version_name: row.version_name,
            notes: row.notes,
            size: row.size as u64,
            sha256: row.sha256,
            uploaded_by: row.uploaded_by,
            created_at: row.created_at,
        }
    }
}

const RELEASE_SELECT: &str =
    "SELECT version_code, version_name, notes, size, sha256, uploaded_by, created_at
                              FROM app_releases";

fn bad_request(msg: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, msg.into())
}

fn not_found(version_code: u32) -> (StatusCode, String) {
    (
        StatusCode::NOT_FOUND,
        format!("no app release with version code {version_code}"),
    )
}

fn check_version_code(version_code: u32) -> Result<(), (StatusCode, String)> {
    if (1..=MAX_APP_VERSION_CODE).contains(&version_code) {
        Ok(())
    } else {
        Err(bad_request(format!(
            "version code must be 1-{MAX_APP_VERSION_CODE}"
        )))
    }
}

async fn find(
    pool: &SqlitePool,
    version_code: u32,
) -> Result<Option<AppRelease>, (StatusCode, String)> {
    let row: Option<ReleaseRow> =
        sqlx::query_as(&format!("{RELEASE_SELECT} WHERE version_code = ?"))
            .bind(version_code)
            .fetch_optional(pool)
            .await
            .map_err(super::internal_error)?;
    Ok(row.map(AppRelease::from))
}

pub async fn list(
    State(pool): State<SqlitePool>,
) -> Result<Json<Vec<AppRelease>>, (StatusCode, String)> {
    let rows: Vec<ReleaseRow> =
        sqlx::query_as(&format!("{RELEASE_SELECT} ORDER BY version_code DESC"))
            .fetch_all(&pool)
            .await
            .map_err(super::internal_error)?;
    Ok(Json(rows.into_iter().map(AppRelease::from).collect()))
}

pub async fn latest(
    State(pool): State<SqlitePool>,
) -> Result<Json<AppRelease>, (StatusCode, String)> {
    let row: Option<ReleaseRow> = sqlx::query_as(&format!(
        "{RELEASE_SELECT} ORDER BY version_code DESC LIMIT 1"
    ))
    .fetch_optional(&pool)
    .await
    .map_err(super::internal_error)?;
    row.map(|row| Json(row.into()))
        .ok_or_else(|| (StatusCode::NOT_FOUND, "no app release uploaded".to_string()))
}

/// Streams the APK of `version_code`.
pub async fn download(
    State(pool): State<SqlitePool>,
    Extension(releases): Extension<Arc<AppReleases>>,
    Path(version_code): Path<u32>,
    req: Request,
) -> Result<Response, (StatusCode, String)> {
    let release = find(&pool, version_code)
        .await?
        .ok_or_else(|| not_found(version_code))?;

    let mut resp = ServeFile::new(releases.apk_path(version_code))
        .oneshot(req)
        .await
        .map_err(super::internal_error)?
        .map(Body::new);
    if resp.status() == StatusCode::NOT_FOUND {
        return Err(super::internal_error(format!(
            "APK of app release {version_code} is missing from disk"
        )));
    }
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(APK_MIME));
    if let Ok(disposition) = HeaderValue::from_str(&format!(
        "attachment; filename=\"pulse-{}.apk\"",
        release.version_name
    )) {
        headers.insert(header::CONTENT_DISPOSITION, disposition);
    }
    Ok(resp)
}

/// Stores the request body as the APK of a new release, then pushes
/// "update available" to every device unless `notify=false`.
pub async fn upload(
    State(pool): State<SqlitePool>,
    Extension(releases): Extension<Arc<AppReleases>>,
    Extension(alerting): Extension<Arc<Alerting>>,
    Extension(user): Extension<AuthedUser>,
    Path(version_code): Path<u32>,
    Query(req): Query<NewAppRelease>,
    body: Body,
) -> Result<Response, (StatusCode, String)> {
    check_version_code(version_code)?;
    if !is_valid_app_version_name(&req.version_name) {
        return Err(bad_request(
            "version_name must be 1-64 printable characters without spaces",
        ));
    }
    let notes = req
        .notes
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty());
    if let Some(notes) = &notes {
        if notes.chars().count() > MAX_APP_RELEASE_NOTES_LEN {
            return Err(bad_request(format!(
                "notes must be at most {MAX_APP_RELEASE_NOTES_LEN} characters"
            )));
        }
        if notes
            .chars()
            .any(|c| c != '\n' && protocol::is_unsafe_display_char(c))
        {
            return Err(bad_request("notes contain control characters"));
        }
    }
    if find(&pool, version_code).await?.is_some() {
        return Err(conflict(version_code));
    }

    let tmp = releases.upload_path();
    let result = store_upload(
        &pool,
        &releases,
        &user,
        version_code,
        &req.version_name,
        notes,
        body,
        &tmp,
    )
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
    }
    let release = result?;

    tracing::warn!(
        version_code,
        version_name = %release.version_name,
        size = release.size,
        by = %user.username,
        "app release uploaded"
    );
    if req.notify.unwrap_or(true) {
        alerting.push().notify_all(
            &pool,
            PushMessage {
                title: "Pulse app update available".to_string(),
                body: format!("Version {} is ready to install.", release.version_name),
                data: vec![("app_version_code", version_code.to_string())],
                what: format!("app release {version_code}"),
            },
        );
    }
    Ok((StatusCode::CREATED, Json(release)).into_response())
}

fn conflict(version_code: u32) -> (StatusCode, String) {
    (
        StatusCode::CONFLICT,
        format!(
            "app release {version_code} already exists; bump the version code or remove it first"
        ),
    )
}

/// Writes `body` to `tmp` while hashing it, records the release and moves
/// the file into place.
#[allow(clippy::too_many_arguments)]
async fn store_upload(
    pool: &SqlitePool,
    releases: &AppReleases,
    user: &AuthedUser,
    version_code: u32,
    version_name: &str,
    notes: Option<String>,
    body: Body,
    tmp: &std::path::Path,
) -> Result<AppRelease, (StatusCode, String)> {
    let too_large = || {
        (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "APK is larger than the server's limit of {} MiB ([app_releases] max_size_mb)",
                releases.max_size() / (1024 * 1024)
            ),
        )
    };

    let mut file = tokio::fs::File::create(tmp)
        .await
        .map_err(super::internal_error)?;
    let mut hasher = Sha256::new();
    let mut size: u64 = 0;
    let mut head = Vec::with_capacity(4);
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| bad_request(format!("reading upload: {e}")))?;
        size += chunk.len() as u64;
        if size > releases.max_size() {
            return Err(too_large());
        }
        if head.len() < 4 {
            let take = (4 - head.len()).min(chunk.len());
            head.extend_from_slice(&chunk[..take]);
        }
        hasher.update(&chunk);
        file.write_all(&chunk)
            .await
            .map_err(super::internal_error)?;
    }
    file.sync_all().await.map_err(super::internal_error)?;
    drop(file);

    // An APK is a ZIP file.
    if head != b"PK\x03\x04" {
        return Err(bad_request("the upload isn't an APK (not a ZIP file)"));
    }
    let sha256: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let inserted = sqlx::query(
        "INSERT INTO app_releases (version_code, version_name, notes, size, sha256, uploaded_by)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(version_code)
    .bind(version_name)
    .bind(&notes)
    .bind(size as i64)
    .bind(&sha256)
    .bind(&user.username)
    .execute(pool)
    .await;
    match inserted {
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(conflict(version_code));
        }
        Err(e) => return Err(super::internal_error(e)),
    }

    if let Err(e) = tokio::fs::rename(tmp, releases.apk_path(version_code)).await {
        let _ = sqlx::query("DELETE FROM app_releases WHERE version_code = ?")
            .bind(version_code)
            .execute(pool)
            .await;
        return Err(super::internal_error(e));
    }

    find(pool, version_code)
        .await?
        .ok_or_else(|| super::internal_error("app release missing after insert"))
}

pub async fn remove(
    State(pool): State<SqlitePool>,
    Extension(releases): Extension<Arc<AppReleases>>,
    Extension(user): Extension<AuthedUser>,
    Path(version_code): Path<u32>,
) -> Result<StatusCode, (StatusCode, String)> {
    let deleted = sqlx::query("DELETE FROM app_releases WHERE version_code = ?")
        .bind(version_code)
        .execute(&pool)
        .await
        .map_err(super::internal_error)?
        .rows_affected();
    if deleted == 0 {
        return Err(not_found(version_code));
    }
    match tokio::fs::remove_file(releases.apk_path(version_code)).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(%e, version_code, "removing app release APK"),
    }
    tracing::warn!(version_code, by = %user.username, "app release removed");
    Ok(StatusCode::NO_CONTENT)
}
